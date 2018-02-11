{-# LANGUAGE DeriveFoldable             #-}
{-# LANGUAGE DeriveFunctor              #-}
{-# LANGUAGE DeriveTraversable          #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase                 #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE TupleSections              #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE ViewPatterns               #-}

module Amazonka.IAM.Policy
    ( Version   (..)

    , Policy    (..)
    , version
    , statement
    , encode

    , Id        (..)
    , Sid       (..)
    , Action    (..)
    , Resource  (..)
    , Principal (..)

    , Match     (..)
    , wildcard

    , Statement (..)
    , allow
    , deny

    , sid
    , condition
    , effect
    , action
    , principal
    , resource

    , Key       (..)
    , Condition (..)
    ) where

import Prelude hiding (not)

import Control.Applicative (optional, (<|>))

import Data.Aeson         (FromJSON, ToJSON (toJSON), (.:), (.:?), (.=))
import Data.Bifunctor     (second)
import Data.ByteString    (ByteString)
import Data.List.NonEmpty (NonEmpty)
import Data.Maybe         (catMaybes)
import Data.Scientific    (Scientific, scientificP)
import Data.Semigroup     (Semigroup ((<>)))
import Data.String        (IsString)
import Data.Text          (Text)
import Data.Time          (UTCTime)

import GHC.Exts (IsList (..))

import qualified Data.Aeson                   as JSON
import qualified Data.Aeson.Types             as JSON
import qualified Data.ByteString.Base64       as Base64
import qualified Data.ByteString.Lazy         as LBS
import qualified Data.List.NonEmpty           as NE
import qualified Data.Text.Encoding           as Text
import qualified Data.Time.Clock.POSIX        as POSIX
import qualified Data.Time.Format             as Time
import qualified Text.ParserCombinators.ReadP as Read

-- | The 'Version' elements specifies the language syntax rules that are to be
-- used to process this policy. If you include features that are not available in
-- the specified version, then your policy will generate errors or not work the
-- way you intend. As a general rule, you should specify the most recent version
-- available, unless you depend on a feature that was deprecated in later
-- versions.
data Version = Version20121017
    deriving (Show, Eq, Ord)

instance Semigroup Version where
    (<>) a _ = a

instance Monoid Version where
    mempty  = Version20121017
    mappend = (<>)

instance ToJSON Version where
    toJSON Version20121017 = JSON.String "2012-10-17"

instance FromJSON Version where
    parseJSON = JSON.withText "Version"$ \case
        "2012-10-17" -> pure Version20121017
        x            -> fail ("Unabled to parse Version from " ++ show x)

-- | A policy document is a non-empty list of IAM statements with a supported
-- version.
newtype Policy a = Policy { statements :: NonEmpty a }
    deriving (Show, Eq, Functor, Foldable, Traversable)

instance Applicative Policy where
    pure                      = statement
    Policy f <*> Policy x = Policy (f <*> x)

instance Eq a => Semigroup (Policy a) where
    (<>) (Policy xs) (Policy ys) = Policy (NE.nub (xs <> ys))

instance ToJSON a => ToJSON (Policy a) where
    toJSON x@(Policy xs) =
        JSON.object
            [ "Version"   .= version x
            , "Statement" .= xs
            ]

instance FromJSON a => FromJSON (Policy a) where
    parseJSON = JSON.withObject "Policy" $ \o ->
        Policy <$ (o .: "Version" :: JSON.Parser Version)
               <*> o .: "Statement"

-- | Obtain the supported version of the policy document.
version :: Policy a -> Version
version = const Version20121017

-- | Create a singleton policy containing only one statement. The 'Semigroup'
-- instance and '(<>)' can be used to combine multiple statements into a larger
-- policy.
statement :: a -> Policy a
statement = Policy . pure

-- | Encode the IAM policy document as JSON.
encode :: Policy Statement -> LBS.ByteString
encode = JSON.encode

-- | The 'Id' element specifies an optional identifier for the policy. The ID
-- is used differently in different services.
--
-- For services that let you set an ID element, we recommend you use a UUID
-- (GUID) for the value, or incorporate a UUID as part of the ID to ensure
-- uniqueness.
--
-- @
-- "Id": "cd3ad3d9-2776-4ef1-a904-4c229d1642ee"
-- @
--
-- /Note/: Some AWS services (for example, Amazon SQS or Amazon SNS) might
-- require this element and have uniqueness requirements for it. For
-- service-specific information about writing policies, refer to the
-- documentation for the service you're working with.
newtype Id = Id Text
    deriving (Show, Eq, Ord, ToJSON, FromJSON, IsString)

-- | The 'Sid' (statement ID) is an optional identifier that you provide for the
-- policy statement. You can assign a Sid value to each statement in a statement
-- array. In services that let you specify an ID element, such as SQS and SNS, the
-- Sid value is just a sub-ID of the policy document's ID. In IAM, the Sid value
-- must be unique within a JSON policy.
--
-- @
-- "Sid": "1"
-- @
--
-- In IAM, the Sid is not exposed in the IAM API. You can't retrieve a
-- particular statement based on this ID.
--
-- /Note/: Some AWS services (for example, Amazon SQS or Amazon SNS) might require this
-- element and have uniqueness requirements for it. For service-specific
-- information about writing policies, refer to the documentation for the service
-- you're working with.
newtype Sid = Sid Text
    deriving (Show, Eq, Ord, ToJSON, FromJSON, IsString)

-- | The 'Effect' element is required and specifies whether the statement
-- results in an allow or an explicit deny.
--
-- By default, access to resources is denied. To allow access to a resource,
-- you must set the Effect element to 'Allow'. To override an allow (for example,
-- to override an allow that is otherwise in force), you set the Effect element
-- to 'Deny'.
data Effect = Allow | Deny
    deriving (Show, Eq, Ord, Enum)

instance ToJSON Effect where
    toJSON = \case
        Allow -> "Allow"
        Deny  -> "Deny"

instance FromJSON Effect where
    parseJSON = JSON.withText "Effect" $ \case
        "Allow" -> pure Allow
        "Deny"  -> pure Deny
        x       -> fail ("Unabled to parse Effect from " ++ show x)

-- | Use the 'Principal' element to specify the user (IAM user, federated user, or
-- assumed-role user), AWS account, AWS service, or other principal entity that
-- is allowed or denied access to a resource. You use the Principal element in
-- the trust policies for IAM roles and in resource-based policies—that is, in
-- policies that you embed directly in a resource. For example, you can embed
-- such policies in an Amazon S3 bucket, an Amazon Glacier vault, an Amazon SNS
-- topic, an Amazon SQS queue, or an AWS KMS customer master key (CMK).
--
-- Use the Principal element in these ways:
--
-- In IAM roles, use the Principal element in the role's trust policy to
-- specify who can assume the role. For cross-account access, you must specify
-- the 12-digit identifier of the trusted account.
--
-- /Note/: After you create the role, you can change the account to "*" to
-- allow everyone to assume the role. If you do this, we strongly recommend
-- that you limit who can access the role through other means, such as a
-- Condition element that limits access to only certain IP addresses. Do not
-- leave your role accessible to everyone!
--
-- In resource-based policies, use the 'Principal' element to specify the
-- accounts or users who are allowed to access the resource.
data Principal
    = Everyone
    | AWS           !(NonEmpty Text)
    | Federated     !Text
    | Service       !(NonEmpty Text)
    | CanonicalUser !Text
      deriving (Show, Eq)

instance ToJSON Principal where
    toJSON = \case
        Everyone         -> JSON.String "*"
        AWS           ks -> JSON.object ["AWS"           .= ks]
        Federated     k  -> JSON.object ["Federated"     .= k]
        Service       ks -> JSON.object ["Service"       .= ks]
        CanonicalUser k  -> JSON.object ["CanonicalUser" .= k]

instance FromJSON Principal where
    parseJSON v = everyone v <|> nested v
      where
        everyone =
            JSON.withText "Principal:*" $ \case
                "*" -> pure Everyone
                x   -> fail ("Unable to parse Principal:* from " ++ show x)

        nested =
            JSON.withObject "Principal" $ \o ->
                    AWS           <$> o .: "AWS"
                <|> Federated     <$> o .: "Federated"
                <|> Service       <$> o .: "Service"
                <|> CanonicalUser <$> o .: "CanonicalUser"

-- | The 'Action' element describes the specific action or actions that will be
-- allowed or denied. Statements must include either an Action or NotAction
-- element. Each AWS service has its own set of actions that describe tasks that
-- you can perform with that service.
newtype Action = Action Text
    deriving (Show, Eq, ToJSON, FromJSON, IsString)

-- | The 'Resource' element specifies the object or objects that the statement
-- covers. Statements must include either a Resource or a NotResource element.
--
-- Each service has its own set of resources. Although you always use an ARN to
-- specify a resource, the details of the ARN for a resource depend on the
-- service and the resource. For information about how to specify a resource,
-- refer to the documentation for the service whose resources you're writing a
-- statement for.
--
-- /Note:/ Some services do not let you specify actions for individual
-- resources; instead, any actions that you list in the Action or NotAction
-- element apply to all resources in that service. In these cases, you use the
-- wildcard @"*"@ in the Resource element.
newtype Resource = Resource Text
    deriving (Show, Eq, ToJSON, FromJSON, IsString)

data Match a
    = Match !a
    | Not   !a
      deriving (Show, Eq, Functor, Foldable, Traversable)

wildcard :: IsString a => Match [a]
wildcard = Match ["*"]

matchToJSON :: ToJSON a => Text -> Match a -> JSON.Pair
matchToJSON k = \case
    Match v -> k .= v
    Not   v -> ("Not" <> k) .= v

matchParseJSON :: FromJSON a => Text -> JSON.Object -> JSON.Parser (Match a)
matchParseJSON k o =
        Match <$> o .: k
    <|> Not   <$> o .: ("Not" <> k)

-- | The 'Statement' element is the main element for a policy. This element is
-- required. It can include multiple elements (see the subsequent sections in this
-- page). The Statement element contains an array of individual statements.
data Statement = Statement
    { _sid       :: !(Maybe Sid)
    , _condition :: !(Maybe Condition)
    , _effect    :: !Effect
    , _action    :: !(Match [Action])
    , _principal :: !(Maybe (Match Principal))
    , _resource  :: !(Maybe (Match [Resource]))
    } deriving (Show, Eq)

instance ToJSON Statement where
    toJSON Statement{..} =
        JSON.object $ catMaybes
            [ fmap ("Sid" .=) _sid
            , fmap ("Condition" .=) _condition
            , Just ("Effect" .= _effect)
            , Just (matchToJSON "Action" _action)
            , matchToJSON "Principal" <$> _principal
            , matchToJSON "Resource"  <$> _resource
            ]

instance FromJSON Statement where
    parseJSON = JSON.withObject "Statement" $ \o -> do
        _sid       <- o .:? "Sid"
        _effect    <- o .:  "Effect"
        _condition <- o .:? "Condition"

        _action    <-
                fmap (:[]) <$> matchParseJSON "Action" o
            <|> matchParseJSON "Action" o

        _resource  <- optional $
                fmap (:[]) <$> matchParseJSON "Resource" o
            <|> matchParseJSON "Resource" o

        _principal <- optional (matchParseJSON "Principal" o)

        pure Statement{..}

-- | Create a new statement with the effect set to 'Allow'.
allow :: Statement
allow = Statement
    { _sid       = Nothing
    , _condition = Nothing
    , _effect    = Allow
    , _action    = Match []
    , _principal = Nothing
    , _resource  = Nothing
    }

-- | Create a new statement with the effect set to 'Deny'.
deny :: Statement
deny = allow { _effect = Deny }

sid :: Functor f
    => (Maybe Sid -> f (Maybe Sid))
    -> Statement
    -> f Statement
sid f s = (\a -> s { _sid = a }) <$> f (_sid s)

condition
    :: Functor f
    => (Maybe Condition -> f (Maybe Condition))
    -> Statement
    -> f Statement
condition f s = (\a -> s { _condition = a }) <$> f (_condition s)

effect
    :: Functor f
    => (Effect -> f Effect)
    -> Statement
    -> f Statement
effect f s = (\a -> s { _effect = a }) <$> f (_effect s)

action
    :: Functor f
    => (Match [Action] -> f (Match [Action]))
    -> Statement
    -> f Statement
action f s = (\a -> s { _action = a }) <$> f (_action s)

principal
    :: Functor f
    => (Maybe (Match Principal) -> f (Maybe (Match Principal)))
    -> Statement
    -> f Statement
principal f s = (\a -> s { _principal = a }) <$> f (_principal s)

resource
    :: Functor f
    => (Maybe (Match [Resource]) -> f (Maybe (Match [Resource])))
    -> Statement
    -> f Statement
resource f s = (\a -> s { _resource = a }) <$> f (_resource s)

-- | A key that will be tested as the target of a 'Condition'.
newtype Key = Key { fromKey :: Text }
    deriving (Show, Eq, FromJSON, ToJSON, IsString)

-- |
--
-- = Conditions
--
-- The 'Condition' element (or Condition block) lets you specify conditions for
-- when a policy is in effect. The Condition element is optional. In the
-- Condition element, you build expressions in which you use condition
-- operators (equal, less than, etc.) to match the condition in the policy
-- against values in the request. Condition values can include date, time, the
-- IP address of the requester, the ARN of the request source, the user name,
-- user ID, and the user agent of the requester. Some services let you specify
-- additional values in conditions; for example, Amazon S3 lets you write a
-- condition using the @s3:VersionId@ key, which is unique to that service.
--
--
-- == String Conditions
--
-- String condition operators let you construct 'Condition' elements that
-- restrict access based on comparing a key to a string value.
--
--
-- == Numeric Conditions
--
-- Numeric condition operators let you construct Condition elements that
-- restrict access based on comparing a key to an integer or decimal value.
--
--
-- == Date Conditions
--
-- Date condition operators let you construct Condition elements that restrict
-- access based on comparing a key to a date/time value. You use these condition
-- operators with the aws:CurrentTime key or aws:EpochTime keys. You must specify
-- date/time values with one of the W3C implementations of the ISO 8601 date
-- formats or in epoch (UNIX) time.
--
-- Wildcards are not permitted for date condition operators.
--
--
-- == Boolean Conditions
--
-- Boolean conditions let you construct Condition elements that restrict access
-- based on comparing a key to "true" or "false."
--
--
-- == Binary Conditions
--
-- The BinaryEquals condition operator let you construct Condition elements
-- that test key values that are in binary format. It compares the value of the
-- specified key byte for byte against a base-64 encoded representation of the
-- binary value in the policy.
--
--
-- == IP Address Conditions
--
-- IP address condition operators let you construct Condition elements that
-- restrict access based on comparing a key to an IPv4 or IPv6 address or range
-- of IP addresses. You use these with the aws:SourceIp key. The value must be
-- in the standard CIDR format (for example, 203.0.113.0/24 or
-- 2001:DB8:1234:5678::/64). If you specify an IP address without the
-- associated routing prefix, IAM uses the default prefix value of /32.
--
-- Some AWS services support IPv6, using :: to represent a range of 0s. To
-- learn whether a service supports IPv6, see the documentation for that
-- service.
--
--
-- == Amazon Resource Name (ARN) Conditions
--
-- Amazon Resource Name (ARN) condition operators let you construct Condition
-- elements that restrict access based on comparing a key to an ARN. The ARN is
-- considered a string. This value is available for only some services; not all
-- services support request values that can be compared as ARNs.
--
--
-- == Key Existence Conditions
--
-- You can add IfExists to the end of any condition operator name except the
-- Null condition—for example, StringLikeIfExists. You do this to say "If the
-- policy key is present in the context of the request, process the key as
-- specified in the policy. If the key is not present, the condition evaluate
-- the condition element as true." Other condition elements in the statement
-- can still result in a nonmatch, but not a missing key when checked with
-- ...IfExists.
--
--
-- == Null Conditions
--
-- Use a Null condition operator to check if a condition key is present at the
-- time of authorization. In the policy statement, use either true (the key
-- doesn't exist — it is null) or false (the key exists and its value is not null).
--
-- For example, you can use this condition operator to determine whether a user is
-- using their own credentials for the operation or temporary credentials. If the
-- user is using temporary credentials, then the key aws:TokenIssueTime exists and
-- has a value. The following example shows a condition that states that the user
-- must not be using temporary credentials (the key must not exist) for the user
-- to use the Amazon EC2 API.
data Condition
    = StringEquals              !Key !Text
    -- ^ Exact matching, case sensitive.
    | StringNotEquals           !Key !Text
    -- ^ Negated matching.
    | StringEqualsIgnoreCase    !Key !Text
    -- ^ Exact matching, ignoring case.
    | StringNotEqualsIgnoreCase !Key !Text
    -- ^ Negated matching, ignoring case
    | StringLike                !Key ![Text]
    -- ^ Case-sensitive matching. The values can include a multi-character match
    -- wildcard (*) or a single-character match wildcard (?) anywhere in the
    -- string.
    --
    -- If a key contains multiple values, StringLike can be qualified with set
    -- operators—ForAllValues:StringLike and ForAnyValue:StringLike. For more
    -- information, see Creating a Condition That Tests Multiple Key Values (Set
    -- Operations).
    | StringNotLike             !Key ![Text]
    -- ^ Negated case-sensitive matching. The values can include a multi-character
    -- match wildcard (*) or a single-character match wildcard (?) anywhere in the
    -- string.

    | NumericEquals             !Key !Scientific
    -- ^ Matching.
    | NumericNotEquals          !Key !Scientific
    -- ^ Negated matching.
    | NumericLessThan           !Key !Scientific
    -- ^ "Less than" matching.
    | NumericLessThanEquals     !Key !Scientific
    -- ^ "Less than or equals" matching.
    | NumericGreaterThan        !Key !Scientific
    -- ^ "Greater than" matching.
    | NumericGreaterThanEquals  !Key !Scientific
    -- ^ "Greater than or equals" matching.

    | DateEquals                !Key !UTCTime
    -- ^ Matching a specific date.
    | DateNotEquals             !Key !UTCTime
    -- ^ Negated matching.
    | DateLessThan              !Key !UTCTime
    -- ^ Matching before a specific date and time.
    | DateLessThanEquals        !Key !UTCTime
    -- ^ Matching at or before a specific date and time.
    | DateGreaterThan           !Key !UTCTime
    -- ^ Matching after a specific a date and time.
    | DateGreaterThanEquals     !Key !UTCTime
    -- ^ Matching at or after a specific date and time.

    | Bool                      !Key !Bool
    -- ^ Boolean matching.

    | BinaryEquals              !Key !ByteString
    -- ^ The BinaryEquals condition operator let you construct Condition elements
    -- that test key values that are in binary format. It compares the value of the
    -- specified key byte for byte against a base-64 encoded representation of the
    -- binary value in the policy.

    | IpAddress                 !Key !ByteString
    -- ^ The specified IP address or range.
    | NotIpAddress              !Key !ByteString
    -- ^ All IP addresses except the specified IP address or range.

    | ArnEquals                 !Key !Text
    -- ^ Case-sensitive matching of the ARN. Each of the six colon-delimited
    -- components of the ARN is checked separately and each can include a
    -- multi-character match wildcard (*) or a single-character match wildcard
    -- (?). These behave identically.
    | ArnLike                   !Key !Text
    -- ^ Case-sensitive matching of the ARN. Each of the six colon-delimited
    -- components of the ARN is checked separately and each can include a
    -- multi-character match wildcard (*) or a single-character match wildcard
    -- (?). These behave identically.
    | ArnNotEquals              !Key !Text
    -- ^ Negated matching for ARN. These behave identically.
    | ArnNotLike                !Key !Text
    -- ^ Negated matching for ARN. These behave identically.
      deriving (Show, Eq)

instance ToJSON Condition where
    toJSON x = JSON.object [op .= JSON.object [key .= val]]
      where
        (op, fromKey -> key, val) =
            case x of
                StringEquals              k v  ->
                    ("StringEquals",              k, toJSON v)
                StringNotEquals           k v  ->
                    ("StringNotEquals",           k, toJSON v)
                StringEqualsIgnoreCase    k v  ->
                    ("StringEqualsIgnoreCase",    k, toJSON v)
                StringNotEqualsIgnoreCase k v  ->
                    ("StringNotEqualsIgnoreCase", k, toJSON v)
                StringLike                k vs ->
                    ("StringLike",                k, toJSON vs)
                StringNotLike             k vs ->
                    ("StringNotLike",             k, toJSON vs)

                NumericEquals             k v  ->
                    ("NumericEquals",             k, toJSON v)
                NumericNotEquals          k v  ->
                    ("NumericNotEquals",          k, toJSON v)
                NumericLessThan           k v  ->
                    ("NumericLessThan",           k, toJSON v)
                NumericLessThanEquals     k v  ->
                    ("NumericLessThanEquals",     k, toJSON v)
                NumericGreaterThan        k v  ->
                    ("NumericGreaterThan",        k, toJSON v)
                NumericGreaterThanEquals  k v  ->
                    ("NumericGreaterThanEquals",  k, toJSON v)

                DateEquals                k v  ->
                    ("DateEquals",                k, toJSON v)
                DateNotEquals             k v  ->
                    ("DateNotEquals",             k, toJSON v)
                DateLessThan              k v  ->
                    ("DateLessThan",              k, toJSON v)
                DateLessThanEquals        k v  ->
                    ("DateLessThanEquals",        k, toJSON v)
                DateGreaterThan           k v  ->
                    ("DateGreaterThan",           k, toJSON v)
                DateGreaterThanEquals     k v  ->
                    ("DateGreaterThanEquals",     k, toJSON v)

                Bool                      k v  ->
                    ("Bool",                      k, toJSON v)

                BinaryEquals              k v  ->
                    ("BinaryEquals",              k,
                        toJSON (Text.decodeUtf8 (Base64.encode v)))

                IpAddress                 k v  ->
                    ("IpAddress",                 k,
                        toJSON (Text.decodeUtf8 v))

                NotIpAddress              k v  ->
                    ("NotIpAddress",              k,
                        toJSON (Text.decodeUtf8 v))

                ArnEquals                 k v  ->
                    ("ArnEquals",                 k, toJSON v)
                ArnLike                   k v  ->
                    ("ArnLike",                   k, toJSON v)
                ArnNotEquals              k v  ->
                    ("ArnNotEquals",              k, toJSON v)
                ArnNotLike                k v  ->
                    ("ArnNotLike",                k, toJSON v)

instance FromJSON Condition where
    parseJSON = JSON.withObject "Condition" $ \o ->
        let parse :: FromJSON a => Text -> JSON.Parser (Key, a)
            parse op = do
                vs <- o .: op
                case toList (vs :: JSON.Object) of
                    [(k, v)] -> (Key k,) <$> JSON.parseJSON v
                    _        ->
                        fail ("Expected one Condition key in " ++ show vs)

            parseNumber op = do
                (k, x) <- parse op
                case Read.readP_to_S scientificP x of
                    [(n, "")] -> pure (k, n)
                    _         ->
                        fail ("Unable to parse numeric Condition from: " ++ show x)

            parseISO8601 op = do
                (k, x) <- parse op
                let fmt    = Time.iso8601DateFormat (Just "%H:%M:%S")
                    locale = Time.defaultTimeLocale
                case Read.readP_to_S (Time.readPTime False locale fmt) x of
                    [(t, "")] -> pure (k, t)
                    _         ->
                        fail ("Unable to parse date Condition from: " ++ show x)

            parsePOSIX op = do
                (k, x) <- parseNumber op
                pure (k, POSIX.posixSecondsToUTCTime (realToFrac x))

            parseDate op =
                parseISO8601 op <|> parsePOSIX op

            parseBool op = do
                (k, x) <- parse op
                case x :: Text of
                    "true"  -> pure (k, True)
                    "false" -> pure (k, False)
                    _       ->
                        fail ("Unable to parse boolean Condition from: " ++ show x)

            parseBinary =
                fmap (second Text.encodeUtf8) . parse

            parseBase64 =
                fmap (second Base64.decodeLenient) . parseBinary

         in uncurry StringEquals
              <$> parse "StringEquals"
        <|> uncurry StringNotEquals
              <$> parse "StringNotEquals"
        <|> uncurry StringEqualsIgnoreCase
              <$> parse "StringEqualsIgnoreCase"
        <|> uncurry StringNotEqualsIgnoreCase
              <$> parse "StringNotEqualsIgnoreCase"
        <|> uncurry StringLike
              <$> parse "StringLike"

        <|> uncurry StringNotLike
              <$> parse "StringNotLike"

        <|> uncurry NumericEquals
             <$> parseNumber "NumericEquals"
        <|> uncurry NumericNotEquals
             <$> parseNumber "NumericNotEquals"
        <|> uncurry NumericLessThan
              <$> parseNumber "NumericLessThan"
        <|> uncurry NumericLessThanEquals
              <$> parseNumber "NumericLessThanEquals"
        <|> uncurry NumericGreaterThan
              <$> parseNumber "NumericGreaterThan"
        <|> uncurry NumericGreaterThanEquals
              <$> parseNumber "NumericGreaterThanEquals"

        <|> uncurry DateEquals
              <$> parseDate "DateEquals"
        <|> uncurry DateNotEquals
              <$> parseDate "DateNotEquals"
        <|> uncurry DateLessThan
              <$> parseDate "DateLessThan"
        <|> uncurry DateLessThanEquals
              <$> parseDate "DateLessThanEquals"
        <|> uncurry DateGreaterThan
              <$> parseDate "DateGreaterThan"
        <|> uncurry DateGreaterThanEquals
              <$> parseDate "DateGreaterThanEquals"

        <|> uncurry Bool
              <$> parseBool "Bool"

        <|> uncurry BinaryEquals
              <$> parseBase64 "BinaryEquals"

        <|> uncurry IpAddress
              <$> parseBinary "IpAddress"
        <|> uncurry NotIpAddress
              <$> parseBinary "NotIpAddress"

        <|> uncurry ArnEquals
              <$> parse "ArnEquals"
        <|> uncurry ArnLike
              <$> parse "ArnLike"
        <|> uncurry ArnNotEquals
              <$> parse "ArnNotEquals"
        <|> uncurry ArnNotLike
              <$> parse "ArnNotLike"

        <|> fail ("Unrecognized Condition: " ++ show o)
