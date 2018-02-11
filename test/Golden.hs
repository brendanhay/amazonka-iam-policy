{-# LANGUAGE OverloadedLists   #-}
{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Amazonka.IAM.Policy (Policy, Statement)

import Data.Aeson     (FromJSON)
import Data.Semigroup ((<>))

import qualified Amazonka.IAM.Policy       as Policy
import qualified Data.Aeson                as JSON
import qualified Data.ByteString.Lazy      as LBS
import qualified Paths_amazonka_iam_policy as Path
import qualified System.IO.Error           as IO
import qualified Test.Hspec                as Hspec

main :: IO ()
main = Hspec.hspec $ do
    test "iam-policy-simulator.json" $
        Policy.singleton
            (Policy.allow
                { Policy.action =
                    Policy.some
                        [ "iam:GetGroup"
                        , "iam:GetGroupPolicy"
                        , "iam:GetPolicy"
                        , "iam:GetPolicyVersion"
                        , "iam:GetRole"
                        , "iam:GetRolePolicy"
                        , "iam:GetUser"
                        , "iam:GetUserPolicy"
                        , "iam:ListAttachedGroupPolicies"
                        , "iam:ListAttachedRolePolicies"
                        , "iam:ListAttachedUserPolicies"
                        , "iam:ListGroups"
                        , "iam:ListGroupPolicies"
                        , "iam:ListGroupsForUser"
                        , "iam:ListRolePolicies"
                        , "iam:ListRoles"
                        , "iam:ListUserPolicies"
                        , "iam:ListUsers"
                        ]
                , Policy.resource = Policy.any
                })

    test "iam-policy-simulator.json" $
        Policy.singleton
            (Policy.allow
                { Policy.action =
                    Policy.some
                        [ "iam:GetGroup"
                        , "iam:GetGroupPolicy"
                        , "iam:GetPolicy"
                        , "iam:GetPolicyVersion"
                        , "iam:GetRole"
                        , "iam:GetRolePolicy"
                        , "iam:GetUser"
                        , "iam:GetUserPolicy"
                        , "iam:ListAttachedGroupPolicies"
                        , "iam:ListAttachedRolePolicies"
                        , "iam:ListAttachedUserPolicies"
                        , "iam:ListGroups"
                        , "iam:ListGroupPolicies"
                        , "iam:ListGroupsForUser"
                        , "iam:ListRolePolicies"
                        , "iam:ListRoles"
                        , "iam:ListUserPolicies"
                        , "iam:ListUsers"
                        ]
                , Policy.resource = Policy.any
                })

    test "iam-user-rotate-credentials.json" $
          Policy.singleton
              (Policy.allow
                  { Policy.action   =
                      Policy.some
                          [ "iam:ListUsers"
                          , "iam:GetAccountPasswordPolicy"
                          ]
                  , Policy.resource = Policy.any
                  })

        <> Policy.singleton
              (Policy.allow
                  { Policy.action   =
                      Policy.some
                          [ "iam:*AccessKey*"
                          , "iam:ChangePassword"
                          , "iam:GetUser"
                          , "iam:*ServiceSpecificCredential*"
                          , "iam:*SigningCertificate*"
                          ]
                  , Policy.resource =
                      Policy.some
                          [ "arn:aws:iam::*:user/${aws:username}"
                          ]
                  })

    test "policy-simulator-api.json" $
        Policy.singleton
            (Policy.allow
                { Policy.action   =
                    Policy.some
                        [ "iam:GetContextKeysForCustomPolicy"
                        , "iam:GetContextKeysForPrincipalPolicy"
                        , "iam:SimulateCustomPolicy"
                        , "iam:SimulatePrincipalPolicy"
                        ]
                , Policy.resource = Policy.any
                })

    test "policy-simulator-console.json" $
           Policy.singleton
               (Policy.allow
                   { Policy.action  =
                       Policy.some
                           [ "iam:GetPolicy"
                           , "iam:GetUserPolicy"
                           ]
                   , Policy.resource = Policy.any
                   })

        <> Policy.singleton
               (Policy.allow
                   { Policy.action   =
                       Policy.some
                           [ "iam:GetUser"
                           , "iam:ListAttachedUserPolicies"
                           , "iam:ListGroupsForUser"
                           , "iam:ListUserPolicies"
                           , "iam:ListUsers"
                           ]
                   , Policy.resource =
                       Policy.some
                           [ "arn:aws:iam::<ACCOUNTNUMBER>:user/<USER-PATH-NAME>/*"
                           ]
                   })

    test "rds-region-admin.json" $
           Policy.singleton
               (Policy.allow
                   { Policy.action   = Policy.some ["rds:*"]
                   , Policy.resource =
                       Policy.some
                           [ "arn:aws:rds:<REGION>:<ACCOUNTNUMBER>:*"
                           ]
                   })

        <> Policy.singleton
               (Policy.allow
                   { Policy.action   = Policy.some ["rds:Describe*"]
                   , Policy.resource = Policy.any
                   })

    test "self-managed-mfa.json" $
           Policy.singleton
               (Policy.allow
                   { Policy.action =
                       Policy.some
                           [ "iam:CreateVirtualMFADevice"
                           , "iam:EnableMFADevice"
                           , "iam:ResyncMFADevice"
                           , "iam:DeleteVirtualMFADevice"
                           ]
                   , Policy.resource =
                       Policy.some
                           [ "arn:aws:iam::*:mfa/${aws:username}"
                           , "arn:aws:iam::*:user/${aws:username}"
                           ]
                   })

        <> Policy.singleton
               (Policy.allow
                   { Policy.sid       =
                       Just "AllowUsersToDeactivateTheirOwnVirtualMFADevice"
                   , Policy.action    =
                       Policy.some
                           [ "iam:DeactivateMFADevice"
                           ]
                   , Policy.resource  =
                       Policy.some
                           [ "arn:aws:iam::*:mfa/${aws:username}"
                           , "arn:aws:iam::*:user/${aws:username}"
                           ]
                   , Policy.condition =
                       Just $ Policy.Bool "aws:MultiFactorAuthPresent" True
                   })

        <> Policy.singleton
               (Policy.allow
                   { Policy.action   =
                       Policy.some
                           [ "iam:ListMFADevices"
                           , "iam:ListVirtualMFADevices"
                           , "iam:ListUsers"
                           ]
                   , Policy.resource = Policy.any
                   })

test :: String -> Policy Statement -> Hspec.Spec
test name actual =
    Hspec.describe name $
        Hspec.it "should equal the serialized haskell value" $
            parseFile ("test/golden/" ++ name)
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
