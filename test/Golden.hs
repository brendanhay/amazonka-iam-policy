{-# LANGUAGE OverloadedLists   #-}
{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Amazonka.IAM.Policy (Policy, Statement)

import Data.Aeson     (FromJSON)
import Data.Semigroup ((<>))

import Lens.Micro ((&), (.~), (?~))

import qualified Amazonka.IAM.Policy       as Policy
import qualified Data.Aeson                as JSON
import qualified Data.ByteString.Lazy      as LBS
import qualified Paths_amazonka_iam_policy as Path
import qualified System.IO.Error           as IO
import qualified Test.Hspec                as Hspec

main :: IO ()
main = Hspec.hspec $ do
    test "iam-policy-simulator.json" $
        Policy.statement
            (Policy.allow
                & Policy.action   .~
                    Policy.Match
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
                & Policy.resource ?~
                    Policy.wildcard)

    test "iam-user-rotate-credentials.json" $
          Policy.statement
              (Policy.allow
                  & Policy.action   .~
                      Policy.Match
                          [ "iam:ListUsers"
                          , "iam:GetAccountPasswordPolicy"
                          ]
                  & Policy.resource ?~
                      Policy.wildcard)

        <> Policy.statement
              (Policy.allow
                  & Policy.action   .~
                      Policy.Match
                          [ "iam:*AccessKey*"
                          , "iam:ChangePassword"
                          , "iam:GetUser"
                          , "iam:*ServiceSpecificCredential*"
                          , "iam:*SigningCertificate*"
                          ]
                  & Policy.resource ?~
                      Policy.Match
                          [ "arn:aws:iam::*:user/${aws:username}"
                          ])

    test "policy-simulator-api.json" $
        Policy.statement
            (Policy.allow
                & Policy.action   .~
                    Policy.Match
                        [ "iam:GetContextKeysForCustomPolicy"
                        , "iam:GetContextKeysForPrincipalPolicy"
                        , "iam:SimulateCustomPolicy"
                        , "iam:SimulatePrincipalPolicy"
                        ]
                & Policy.resource ?~
                    Policy.wildcard)

    test "policy-simulator-console.json" $
           Policy.statement
               (Policy.allow
                   & Policy.action  .~
                       Policy.Match
                           [ "iam:GetPolicy"
                           , "iam:GetUserPolicy"
                           ]
                   & Policy.resource ?~
                       Policy.wildcard)

        <> Policy.statement
               (Policy.allow
                   & Policy.action   .~
                       Policy.Match
                           [ "iam:GetUser"
                           , "iam:ListAttachedUserPolicies"
                           , "iam:ListGroupsForUser"
                           , "iam:ListUserPolicies"
                           , "iam:ListUsers"
                           ]
                   & Policy.resource ?~
                       Policy.Match
                           [ "arn:aws:iam::<ACCOUNTNUMBER>:user/<USER-PATH-NAME>/*"
                           ])

    test "rds-region-admin.json" $
           Policy.statement
               (Policy.allow
                   & Policy.action   .~
                       Policy.Match
                           [ "rds:*"
                           ]
                   & Policy.resource ?~
                       Policy.Match
                           [ "arn:aws:rds:<REGION>:<ACCOUNTNUMBER>:*"
                           ])

        <> Policy.statement
               (Policy.allow
                   & Policy.action   .~
                       Policy.Match
                           [ "rds:Describe*"
                           ]
                   & Policy.resource ?~
                       Policy.wildcard)

    test "self-managed-mfa.json" $
           Policy.statement
               (Policy.allow
                   & Policy.action   .~
                       Policy.Match
                           [ "iam:CreateVirtualMFADevice"
                           , "iam:EnableMFADevice"
                           , "iam:ResyncMFADevice"
                           , "iam:DeleteVirtualMFADevice"
                           ]
                   & Policy.resource ?~
                       Policy.Match
                           [ "arn:aws:iam::*:mfa/${aws:username}"
                           , "arn:aws:iam::*:user/${aws:username}"
                           ])

        <> Policy.statement
               (Policy.allow
                   & Policy.sid       ?~
                       "AllowUsersToDeactivateTheirOwnVirtualMFADevice"
                   & Policy.action    .~
                       Policy.Match
                           [ "iam:DeactivateMFADevice"
                           ]
                   & Policy.resource  ?~
                       Policy.Match
                           [ "arn:aws:iam::*:mfa/${aws:username}"
                           , "arn:aws:iam::*:user/${aws:username}"
                           ]
                   & Policy.condition ?~
                       Policy.Bool "aws:MultiFactorAuthPresent" True)

        <> Policy.statement
               (Policy.allow
                   & Policy.action   .~
                       Policy.Match
                           [ "iam:ListMFADevices"
                           , "iam:ListVirtualMFADevices"
                           , "iam:ListUsers"
                           ]
                   & Policy.resource ?~
                       Policy.wildcard)

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
