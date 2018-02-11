module Main (main) where

import Test.DocTest (doctest)

main :: IO ()
main = doctest ["-isrc", "--fast", "src/Amazonka/IAM/Policy.hs"]
