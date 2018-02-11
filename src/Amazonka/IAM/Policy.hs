{-# LANGUAGE DeriveFoldable             #-}
{-# LANGUAGE DeriveFunctor              #-}
{-# LANGUAGE DeriveTraversable          #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase                 #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE RankNTypes                 #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE TypeFamilies               #-}

module Amazonka.IAM.Policy where

import Prelude hiding (negate, not)

import Control.Applicative ((<|>))

import Data.Aeson             (FromJSON, ToJSON (toJSON), (.:), (.:?), (.=))
import Data.Functor.Identity  (Identity (..))
import Data.List.NonEmpty     (NonEmpty (..))
import Data.Maybe             (catMaybes)
import Data.Profunctor        (dimap)
import Data.Profunctor.Choice (Choice (right'))
import Data.Semigroup         (Semigroup ((<>)))
import Data.String            (IsString (fromString))
import Data.Text              (Text)

import GHC.Exts (IsList (..))

import qualified Data.Aeson         as JSON
import qualified Data.Aeson.Types   as JSON
import qualified Data.List.NonEmpty as NE

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

-- FIXME: Deliberately no IsString instances so people have to write Action "foo", Id "foo", etc.

newtype Document a = Document (NonEmpty a)
    deriving (Show, Eq, Functor, Foldable, Traversable)

instance IsList (Document a) where
    type Item (Document a) = a

    toList (Document xs) = NE.toList xs
    fromList             = Document . NE.fromList

instance Applicative Document where
    pure                      = statement
    Document f <*> Document x = Document (f <*> x)

instance Eq a => Semigroup (Document a) where
    (<>) (Document xs) (Document ys) = Document (NE.nub (xs <> ys))

instance ToJSON a => ToJSON (Document a) where
    toJSON (Document xs) =
        JSON.object
            [ "Version"   .= ("2012-10-17" :: Text)
            , "Statement" .= xs
            ]

instance FromJSON a => FromJSON (Document a) where
    parseJSON = JSON.withObject "Document" $ \o ->
        Document <$ (o .: "Version" :: JSON.Parser Version)
                 <*> o .: "Statement"

statement :: a -> Document a
statement = Document . pure

-- document :: Statement ->

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

-- | The 'Statement' element is the main element for a policy. This element is
-- required. It can include multiple elements (see the subsequent sections in this
-- page). The Statement element contains an array of individual statements.
data Statement = Statement
    { _sid       :: !(Maybe Sid)
    , _effect    :: !Effect
    , _condition :: !(Maybe Condition)
    , _action    :: !(Match [Action])
    , _resource  :: !(Maybe (Match [Resource]))
    , _principal :: !(Maybe (Match Principal))
    } deriving (Show, Eq)

instance ToJSON Statement where
    toJSON Statement{..} =
        let match k = \case
              Any v -> k .= v
              Not v -> ("Not" <> k) .= v
         in JSON.object $ catMaybes
            [ fmap ("Sid"       .=)    _sid
            , Just ("Effect"    .=     _effect)
            , fmap ("Condition" .=)    _condition
            , Just (match "Action"     _action)
            , fmap (match "Resource")  _resource
            , fmap (match "Principal") _principal
            ]

instance FromJSON Statement where
    parseJSON = JSON.withObject "Statement" $ \o -> do
        let match :: FromJSON a => Text -> JSON.Parser (Match a)
            match k = Any <$> o .: k
                  <|> Not <$> o .: ("Not" <> k)

        _sid       <- o .:? "Sid"
        _effect    <- o .:  "Effect"
        _condition <- o .:? "Condition"

        _action    <- match "Action"
                  <|> fmap (:[]) <$> match "Action"

        _resource  <- Just <$> match "Resource"
                  <|> Just . fmap (:[]) <$> match "Resource"
                  <|> pure Nothing

        _principal <- Just <$> match "Principal"
                  <|> pure Nothing

        pure Statement{..}

allow :: Statement
allow = Statement
    { _effect    = Allow
    , _action    = Any []
    , _sid       = Nothing
    , _principal = Nothing
    , _resource  = Nothing
    , _condition = Nothing
    }

deny :: Statement
deny = allow { _effect = Deny }

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

sid :: Functor f
    => (Maybe Sid -> f (Maybe Sid))
    -> Statement
    -> f Statement
sid f s = (\a -> s { _sid = a }) <$> f (_sid s)

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

condition
    :: Functor f
    => (Maybe Condition -> f (Maybe Condition))
    -> Statement
    -> f Statement
condition f s = (\a -> s { _condition = a }) <$> f (_condition s)

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
    parseJSON = \case
        JSON.String "*" -> pure Everyone

      -- JSON.withObject "Principal" $ \o ->
      -- where
      --   everyone = JSON.withText "*"

-- | The 'Action' element describes the specific action or actions that will be
-- allowed or denied. Statements must include either an Action or NotAction
-- element. Each AWS service has its own set of actions that describe tasks that
-- you can perform with that service.
newtype Action = Action Text
    deriving (Show, Eq, Ord, ToJSON, FromJSON, IsString)

-- instance FromJSON Action where
--     parseJSON = fmap Action . \case
--         (JSON.String s) -> pure (pure s)
--         o               -> JSON.parseJSON o

-- instance IsList Action where
--     type Item Action = Text

--     toList (Action xs) = xs
--     fromList           = Action

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
-- wildcard * in the Resource element.
newtype Resource = Resource Text
    deriving (Show, Eq, Ord, ToJSON, FromJSON, IsString)

-- instance IsList Resource where
--     type Item Resource = Text

--     toList (Resource xs) = xs
--     fromList             = Resource

-- instance FromJSON Resource where
--     parseJSON = fmap Resource . \case
--         JSON.String s -> pure (pure s)
--         o             -> JSON.parseJSON o

-- | The 'Condition' element (or Condition block) lets you specify conditions for when
-- a policy is in effect. The Condition element is optional. In the Condition
-- element, you build expressions in which you use condition operators (equal,
-- less than, etc.) to match the condition in the policy against values in the
-- request. Condition values can include date, time, the IP address of the
-- requester, the ARN of the request source, the user name, user ID, and the user
-- agent of the requester. Some services let you specify additional values in
-- conditions; for example, Amazon S3 lets you write a condition using the
-- @s3:VersionId@ key, which is unique to that service.
data Condition = Condition
    deriving (Show, Eq)

instance ToJSON Condition where
    toJSON = const JSON.Null

instance FromJSON Condition where
    parseJSON = const (pure Condition)

data Match a
    = Any !a
    | Not !a
      deriving (Show, Eq, Functor, Foldable, Traversable)

wildcard :: IsString a => Match [a]
wildcard = Any [fromString "*"]

_Any :: Prism (Match a) (Match a) a a
_Any =
    prism Any $ \case
        Any x -> Right x
        y     -> Left  y

_Not :: Prism (Match a) (Match a) a a
_Not =
    prism Not $ \case
        Not x -> Right x
        y     -> Left  y

type Lens s t a b = forall f. Functor f => (a -> f b) -> s -> f t

lens :: (s -> a) -> (s -> b -> t) -> Lens s t a b
lens sa sbt afb s = sbt s <$> afb (sa s)
{-# INLINE lens #-}

type Prism s t a b = forall p f. (Choice p, Applicative f) => p a (f b) -> p s (f t)

prism :: (b -> t) -> (s -> Either t a) -> Prism s t a b
prism bt seta = dimap seta (either pure (fmap bt)) . right'
{-# INLINE prism #-}
