{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PackageImports #-}

-- Benchmarks for the Haskell Nix libraries
-- (nix-narinfo, nix-derivation, hnix-store-core, hnix-store-nar, ed25519).
-- Mirrors bench/zig/src/main.zig: same corpus, same output format
-- (`<name> <ops> <best-round-ns>`), best of 7 rounds after a warm-up.
--
-- Inputs are pre-decoded to Text outside the timed region, which favours
-- these libraries (our Zig parsers work on raw bytes).

module Main (main) where

import Control.Exception (evaluate)
import Control.Monad (forM, replicateM, when)
import qualified "crypton" Crypto.Hash as H
import qualified Crypto.Sign.Ed25519 as Ed
import qualified Data.Attoparsec.Text as A
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Char8 as BC
import Data.IORef
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Text.Lazy as TL
import qualified Data.Text.Lazy.Builder as TB
import Data.Word (Word64)
import GHC.Clock (getMonotonicTimeNSec)
import qualified Nix.Derivation as D
import Nix.NarInfo (NarInfo (..))
import qualified Nix.NarInfo as NI
import qualified "hnix-store-core" System.Nix.Base32 as B32
import qualified "hnix-store-nar" System.Nix.Nar.Streamer as Nar
import qualified "hnix-store-core" System.Nix.StorePath as SP
import System.Environment (getEnv, lookupEnv)

rounds :: Int
rounds = 7

records :: FilePath -> IO [BS.ByteString]
records path = filter (not . BS.null) . BS.split 0 <$> BS.readFile path

report :: String -> Int -> Word64 -> IO ()
report name ops ns = putStrLn (name ++ " " ++ show ops ++ " " ++ show ns)

-- Applies `f` to `x` afresh every round. NOINLINE plus -fno-full-laziness
-- keep GHC from sharing one evaluation across rounds.
{-# NOINLINE bench #-}
bench :: String -> Int -> (a -> Int) -> a -> IO ()
bench name ops f x = do
  _ <- evaluate (f x)
  times <- replicateM rounds $ do
    t0 <- getMonotonicTimeNSec
    !_ <- evaluate (f x)
    t1 <- getMonotonicTimeNSec
    pure (t1 - t0)
  report name ops (minimum times)

forceNarInfo :: NI.SimpleNarInfo -> Int
forceNarInfo ni =
  length (storePath ni) + T.length (url ni) + T.length (compression ni) + T.length (fileHash ni)
    + fromIntegral (fileSize ni) + T.length (narHash ni) + fromIntegral (narSize ni)
    + sum (map length (Set.toList (references ni)))
    + maybe 0 T.length (deriver ni) + maybe 0 T.length (system ni) + maybe 0 T.length (sig ni)

forceDrv :: D.Derivation FilePath T.Text -> Int
forceDrv d =
  sum [length (D.path o) + T.length (D.hashAlgo o) + T.length (D.hash o) + T.length k | (k, o) <- Map.toList (D.outputs d)]
    + sum [length p + sum (map T.length (Set.toList os)) | (p, os) <- Map.toList (D.inputDrvs d)]
    + sum (map length (Set.toList (D.inputSrcs d)))
    + T.length (D.platform d) + T.length (D.builder d) + sum (fmap T.length (D.args d))
    + sum [T.length k + T.length v | (k, v) <- Map.toList (D.env d)]

parseText :: A.Parser a -> T.Text -> a
parseText p t = either error id (A.parseOnly p t)

-- Nix secret key file: "<name>:<base64 of 64 bytes>".
signer :: BS.ByteString -> (BS.ByteString, Ed.SecretKey)
signer key =
  let (name, rest) = BC.break (== ':') (BC.strip key)
   in (name, Ed.SecretKey (either error id (B64.decode (BS.drop 1 rest))))

main :: IO ()
main = do
  dir <- getEnv "BENCH_DIR"
  only <- maybe "" id <$> lookupEnv "BENCH_ONLY"
  paths <- records (dir ++ "/paths.bin")

  when (only == "nar") $ do
    t0 <- getMonotonicTimeNSec
    total <- fmap sum . forM paths $ \p -> do
      ref <- newIORef (H.hashInit :: H.Context H.SHA256)
      size <- newIORef (0 :: Int)
      Nar.dumpPath (BC.unpack p) $ \chunk -> do
        modifyIORef' ref (`H.hashUpdate` chunk)
        modifyIORef' size (+ BS.length chunk)
      digest <- H.hashFinalize <$> readIORef ref
      _ <- evaluate (length (show digest))
      readIORef size
    t1 <- getMonotonicTimeNSec
    report "nar-dump-sha256" total (t1 - t0)

  when (only /= "nar") $ do
    narinfos <- map TE.decodeUtf8 <$> records (dir ++ "/narinfo.bin")
    drvs <- map TE.decodeUtf8 <$> records (dir ++ "/drv.bin")
    let parsed = map (parseText NI.parseNarInfo) narinfos
    _ <- evaluate (sum (map forceNarInfo parsed))
    let hashes32 = [T.take 32 (T.drop 11 (T.pack (storePath ni))) | ni <- parsed]
        hashes52 = [T.drop 7 (narHash ni) | ni <- parsed]
        raw20 = [either error id (B32.decode h) | h <- hashes32]
        fingerprints =
          [ TE.encodeUtf8 (T.intercalate ";" ["1", T.pack (storePath ni), narHash ni, T.pack (show (narSize ni)), T.unwords (map T.pack (Set.toList (references ni)))])
          | ni <- parsed
          ]
    _ <- evaluate (sum (map BS.length raw20) + sum (map BS.length fingerprints) + sum (map T.length hashes52))
    (keyName, sk) <- signer <$> BS.readFile (dir ++ "/key")

    bench "narinfo-parse" (length narinfos) (sum . map (forceNarInfo . parseText NI.parseNarInfo)) narinfos
    bench "narinfo-render" (length parsed) (sum . map (fromIntegral . TL.length . TB.toLazyText . NI.buildNarInfo)) parsed
    bench "ed25519-sign" (length fingerprints) (\fps -> sum [BS.length (keyName <> ":" <> B64.encode (Ed.unSignature (Ed.dsign sk fp))) | fp <- fps]) fingerprints
    bench "drv-parse" (length drvs) (sum . map (forceDrv . parseText D.parseDerivation)) drvs
    bench "base32-decode-20" (length hashes32) (\hs -> sum [either error BS.length (B32.decode h) | h <- hs]) hashes32
    bench "base32-decode-32" (length hashes52) (\hs -> sum [either error BS.length (B32.decode h) | h <- hs]) hashes52
    bench "base32-encode-20" (length raw20) (sum . map (T.length . B32.encode)) raw20
    bench "storepath-parse" (length paths) (\ps -> sum [either error (\sp -> SP.storePathHash sp `seq` SP.storePathName sp `seq` 1) (SP.parsePath "/nix/store" p) | p <- ps]) paths
