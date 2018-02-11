{-# LANGUAGE OverloadedLists   #-}
{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Data.Aeson     (FromJSON, ToJSON)
import Data.Function  ((&))
import Data.Semigroup ((<>))

import qualified Amazonka.IAM.Policy       as Policy
import qualified Data.Aeson                as JSON
import qualified Data.ByteString.Lazy      as LBS
import qualified Paths_amazonka_iam_policy as Path
import qualified System.IO.Error           as IO
import qualified Test.Hspec                as Hspec

main :: IO ()
main =
    Hspec.hspec $
        Hspec.describe "golden tests" $ do
            test "test/golden/policy-simulator-api.json" $
                Policy.document
                    (Policy.allow
                        [ "iam:GetContextKeysForCustomPolicy"
                        , "iam:GetContextKeysForPrincipalPolicy"
                        , "iam:SimulateCustomPolicy"
                        , "iam:SimulatePrincipalPolicy"
                        ]) { Policy.resource = Just
                               [ "*"
                               ]
                           }

            test "test/golden/self-managed-mfa.json" $
                   Policy.document
                       (Policy.allow
                           [ "iam:CreateVirtualMFADevice"
                           , "iam:EnableMFADevice"
                           , "iam:ResyncMFADevice"
                           , "iam:DeleteVirtualMFADevice"
                           ]) { Policy.resource = Just
                                   [ "arn:aws:iam::*:mfa/${aws:username}"
                                   , "arn:aws:iam::*:user/${aws:username}"
                                   ]
                              }
                <> Policy.document
                       (Policy.allow
                           [ "iam:DeactivateMFADevice"
                           ]) { Policy.sid = Just
                                  "AllowUsersToDeactivateTheirOwnVirtualMFADevice"
                              , Policy.resource = Just
                                   [ "arn:aws:iam::*:mfa/${aws:username}"
                                   , "arn:aws:iam::*:user/${aws:username}"
                                   ]
                              , Policy.condition = Just
                                  Policy.Condition
                              }
                <> Policy.document
                       (Policy.allow
                           [ "iam:ListMFADevices"
                           , "iam:ListVirtualMFADevices"
                           , "iam:ListUsers"
                           ]) { Policy.resource = Just
                                  [ "*"
                                  ]
                              }

test :: (Show a, Eq a, FromJSON a, ToJSON a) => String -> a -> Hspec.Spec
test name actual =
    Hspec.it name $
        parseFile name
            >>= Hspec.shouldBe actual

parseFile :: FromJSON a => String -> IO a
parseFile name = do
    path <- Path.getDataFileName name
    lbs  <- LBS.readFile path
    case JSON.eitherDecode' lbs of
        Right x -> pure x
        Left  e ->
            IO.ioError $
                IO.userError ("Failed parsing " ++ path ++ ": " ++ e)
