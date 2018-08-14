{-# LANGUAGE DeriveFoldable             #-}
{-# LANGUAGE DeriveFunctor              #-}
{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE DeriveTraversable          #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase                 #-}
{-# LANGUAGE OverloadedLists            #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE TupleSections              #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE ViewPatterns               #-}

{- | This module provides data types and combinators that allow you to declare,
encode, and decode the
<https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies.html IAM JSON policy>
language. The available 'Action' and 'Condition' keys can be found under the
<https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_actionsconditions.html AWS Service Actions and Condition Context Keys for Use in IAM policies>
documentation.

Lenses and prisms for those wanting to traverse and manipulate policy documents
and their constituent elements can be found in the "Amazonka.IAM.Policy.Lens"
module.
-}
module Amazonka.IAM.Policy
    (
    -- * Usage
    -- $usage

    -- * Policy Documents
      Document
    , Policy    (..)

    -- ** Constructing Policies
    , document
    , singleton

    -- ** Encoding
    , encode

    -- * Language Elements
    -- $elements

    , Block     (..)
    , Match     (..)

    -- ** Specifying and Negating Elements
    , some
    , not
    , any
    , none

    -- ** Version
    , Version   (..)

    -- ** Id
    , Id        (..)

    -- ** Statement
    , Statement (..)

    -- *** Constructing Statements
    , allow
    , deny

    -- ** Sid
    , Sid       (..)

    -- ** Principal
    , Principal (..)

    -- ** Effect
    , Effect    (..)

    -- ** Action
    , Action    (..)

    -- ** Resource
    , Resource  (..)

    -- ** Condition
    , Key       (..)
    , Condition (..)
    ) where

import Prelude hiding (any, id, not)

import Control.Applicative (optional, (<|>))

import Data.Aeson         (FromJSON, ToJSON (toJSON), (.:), (.:?), (.=))
import Data.Bifunctor     (second)
import Data.ByteString    (ByteString)
import Data.Function      (on)
import Data.Hashable      (Hashable (hashWithSalt))
import Data.List.NonEmpty (NonEmpty)
import Data.Maybe         (catMaybes)
import Data.Scientific    (Scientific, scientificP)
import Data.Semigroup     (Semigroup ((<>)))
import Data.String        (IsString)
import Data.Text          (Text)
import Data.Time          (UTCTime)

import GHC.Exts     (IsList (..))
import GHC.Generics (Generic)

import qualified Data.Aeson                   as JSON
import qualified Data.Aeson.Types             as JSON
import qualified Data.ByteString.Base64       as Base64
import qualified Data.ByteString.Lazy         as LBS
import qualified Data.List.NonEmpty           as NE
import qualified Data.Text.Encoding           as Text
import qualified Data.Time                    as Time
import qualified Data.Time.Clock.POSIX        as POSIX
import qualified Text.ParserCombinators.ReadP as Read

{- $setup

>>> :set -XOverloadedStrings

>>> import Data.Aeson.Encode.Pretty (encodePretty)
>>> import Data.ByteString.Lazy.Char8 (unpack)

>>> let encode' = putStrLn . unpack . encodePretty

-}

{- $usage
It's recommended that you import and use this module qualified to avoid any
ambiguity with prelude functions.

The following is an example of using the 'Semigroup' instance of 'Policy' to
construct a document from multiple statements. This example creates a policy
that would allow an IAM user sufficient privilege to rotate their credentials:

@
&#x7b;-\# LANGUAGE OverloadedStrings \#-&#x7d;

import qualified Amazonka.IAM.Policy as Policy

 ( Policy.singleton
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
 )
@

Which results in the following encoded IAM JSON policy document:

> {
>   "Version": "2012-10-17",
>   "Statement": [
>     {
>       "Effect": "Allow",
>       "Action": [
>         "iam:ListUsers",
>         "iam:GetAccountPasswordPolicy"
>       ],
>       "Resource": "*"
>     },
>     {
>       "Effect": "Allow",
>       "Action": [
>         "iam:*AccessKey*",
>         "iam:ChangePassword",
>         "iam:GetUser",
>         "iam:*ServiceSpecificCredential*",
>         "iam:*SigningCertificate*"
>       ],
>       "Resource": "arn:aws:iam::*:user/${aws:username}"
>     }
>   ]
> }

You can also use the @OverloadedLists@ extension with the 'document' smart constructor
to create a 'Policy' using the 'IsList' instance for 'NonEmpty'. The following example
sets up S3 bucket management:

@
&#x7b;-\# LANGUAGE OverloadedLists   \#-&#x7d;
&#x7b;-\# LANGUAGE OverloadedStrings \#-&#x7d;

import qualified Amazonka.IAM.Policy as Policy

Policy.document
    [ Policy.allow
        { Policy.action   = Policy.some ["s3:*"]
        , Policy.resource =
            Policy.some
                [ "arn:aws:s3:::<BUCKET-NAME>"
                , "arn:aws:s3:::<BUCKET-NAME>/*"
                ]
        }
    , Policy.deny
        { Policy.action   = Policy.not ["s3:*"]
        , Policy.resource =
            Policy.not
                [
                , "arn:aws:s3:::<BUCKET-NAME>"
                , "arn:aws:s3:::<BUCKET-NAME>/*"
                ]
        }
    ]
@

Resulting in the following encoded IAM JSON policy document:

> {
>   "Version": "2012-10-17",
>   "Statement": [
>     {
>       "Effect": "Allow",
>       "Action": "s3:*",
>       "Resource": [
>         "arn:aws:s3:::<BUCKET-NAME>",
>         "arn:aws:s3:::<BUCKET-NAME>/*"
>       ]
>     },
>     {
>       "Effect": "Deny",
>       "NotAction": "s3:*",
>       "NotResource": [
>         "arn:aws:s3:::<BUCKET-NAME>",
>         "arn:aws:s3:::<BUCKET-NAME>/*"
>       ]
>     }
>   ]
> }

Please be aware that the use of @OverloadedLists@ and 'NonEmpty' will error if
'document' is passed an empty list.
-}

{- $elements
IAM JSON policy documents are made up of elements. The elements are listed here
roughly in the general order you use them in a policy.

The details of what goes into a policy vary for each service, depending on what
actions the service makes available, what types of resources it contains, and
so on. When you're writing policies for a specific service, it's helpful to see
examples of policies for that service. View the <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_aws-services-that-work-with-iam.html AWS Services That Work with IAM>
documentation for more information.

This library attempts to stick as closely as possible to the IAM policy language grammar
and its specific terminology while providing a modicum of safety without going
overboard with type-level features. To support this, the concept of @Element@ vs
@NotElement@ and @"*"@ wildcards are generalised by the introduction of two
additional types not specified directly in the <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html language grammar>.

Firstly there is the 'Block' type which allows us to negate @Principal@,
@Action@, and @Resource@ elements via the related @NotPrincipal@, @NotAction@,
and @NotResource@ elements. Secondly the @Match@ type provides a way to
generally specific @Some@ values for an element, or the @Wildcard@ match
equivalent to @"*"@. Combinators are then provided for the common cases.

==== Example

>>> encode' $ singleton (allow { action = some ["foo", "bar"] })
...
            "Effect": "Allow",
            "Action": [
                "foo",
                "bar"
            ]
...

>>> encode' $ singleton (allow { action = not ["baz"] })
...
            "Effect": "Allow",
            "NotAction": "baz"
...

>>> encode' $ singleton (allow { action = any })
...
            "Effect": "Allow",
            "Action": "*"
...

>>> encode' $ singleton (allow { action = none })
...
            "Effect": "Allow",
            "NotAction": "*"
...

The above examples work identically for the 'action', 'resource', and
'principal' statement elements.

-}

{- | A 'Block' is a shared type denoting blocks of the policy language grammar.

This is used by the 'Principal', 'Action', 'Resource' elements of the policy
language.

==== Grammar

> <name_block> = ("Name" | "NotName") : <match_block>
-}
data Block a
    = Match !(Match a)
    | Not   !(Match a)
      deriving (Show, Eq, Ord, Generic, Functor, Foldable, Traversable)

instance Hashable a => Hashable (Block a)

blockToJSON :: ToJSON a => Text -> Block a -> JSON.Pair
blockToJSON k = \case
    Match v -> k .= v
    Not   v -> ("Not" <> k) .= v
{-# INLINE blockToJSON #-}

blockParseJSON :: FromJSON a => Text -> JSON.Object -> JSON.Parser (Block a)
blockParseJSON k o =
        Match <$> o .: k
    <|> Not   <$> o .: ("Not" <> k)
{-# INLINE blockParseJSON #-}

-- | Match one or more elements.
some :: a -> Block a
some = Match . Some
{-# INLINEABLE some #-}

-- | Negate a match of one or more elements.
--
-- `not` is the negation of `some`.
not :: a -> Block a
not = Not . Some
{-# INLINEABLE not #-}

-- | Match any element with a wildcard.
any :: Block a
any = Match Wildcard
{-# INLINEABLE any #-}

-- | Match no element with a negated wildcard.
--
-- `none` is the negation of `any`.
none :: Block a
none = Not Wildcard
{-# INLINEABLE none #-}

{- | A 'Match' is a shared type used to denote wildcards in the policy
language grammar.

This is used by the 'Principal', 'Action', 'Resource' elements of the policy
language.

==== Grammar

> <match_block> = ("*" | <item>)
-}
data Match a
    = Some !a
    | Wildcard
      deriving (Show, Eq, Ord, Generic, Functor, Foldable, Traversable)

instance Hashable a => Hashable (Match a)

instance Semigroup a => Semigroup (Match a) where
    (<>) a b =
        case (a, b) of
            (Wildcard, _)        -> Wildcard
            (_,        Wildcard) -> Wildcard
            (Some xs,  Some ys)  -> Some (xs <> ys)
    {-# INLINEABLE (<>) #-}

instance (Semigroup a, Monoid a) => Monoid (Match a) where
    mempty = Some mempty
    {-# INLINEABLE mempty #-}

    mappend = (<>)
    {-# INLINEABLE mappend #-}

instance ToJSON a => ToJSON (Match a) where
    toJSON = \case
        Some x   -> toJSON x
        Wildcard -> JSON.String "*"
    {-# INLINE toJSON #-}

instance FromJSON a => FromJSON (Match a) where
    parseJSON = \case
        JSON.String "*"  -> pure Wildcard
        JSON.Array ["*"] -> pure Wildcard
        x                -> Some <$> JSON.parseJSON x
    {-# INLINE parseJSON #-}

-- | This type is used to provide support for interchangeably encoding or parsing
-- a single value, or multiple values as a list.
data OneOrMany a
    = One  !a
    | Many ![a]
      deriving (Show, Eq, Ord, Generic, Functor, Foldable, Traversable)

instance Hashable a => Hashable (OneOrMany a)

instance ToJSON a => ToJSON (OneOrMany a) where
    toJSON = \case
        One  x  -> toJSON x
        Many xs -> toJSON xs
    {-# INLINE toJSON #-}

instance FromJSON a => FromJSON (OneOrMany a) where
    parseJSON o = One <$> JSON.parseJSON o <|> Many <$> JSON.parseJSON o
    {-# INLINE parseJSON #-}

instance IsList (OneOrMany a) where
    type Item (OneOrMany a) = a

    toList = \case
        One  x -> [x]
        Many xs -> xs
    {-# INLINE toList #-}

    fromList = \case
        [x] -> One  x
        xs  -> Many xs
    {-# INLINE fromList #-}

{- | A policy document is a non-empty list of IAM statements with a supported version.

The statements of a policy document can be traversed and manipulated via the
'Functor', 'Foldable', and 'Traverseable' instances. You can use the
'Semigroup' instance to concatenate multiple 'Policy' documents together,
preserving the highest supported version and first encountered 'Id'.

==== Grammar

> policy  = {
>     <version_block?>
>     <id_block?>
>     <statement_block>
> }

-}
type Document = Policy Statement

data Policy a = Policy
    { version   :: !(Maybe Version)
    , id        :: !(Maybe Id)
    , statement :: !(NonEmpty a)
    } deriving (Show, Eq, Ord, Generic, Functor, Foldable, Traversable)

instance Hashable a => Hashable (Policy a)

-- FIXME: Note about pointwise 'First' behaviour of version/id.
instance Semigroup (Policy a) where
    (<>) a b = Policy
        { version   = on (<>)  version   a b
        , id        = on (<|>) id        a b
        , statement = on (<>)  statement a b
        }
    {-# INLINEABLE (<>) #-}

instance ToJSON a => ToJSON (Policy a) where
    toJSON Policy{..} =
        JSON.object $ catMaybes
            [ fmap ("Id"        .=) id
            , fmap ("Version"   .=) version
            , Just ("Statement" .=  statement)
            ]
    {-# INLINEABLE toJSON #-}

instance FromJSON a => FromJSON (Policy a) where
    parseJSON = JSON.withObject "Policy" $ \o -> do
        version   <- o .:? "Version"
        id        <- o .:? "Id"
        statement <- o .:  "Statement"
        pure Policy{..}
    {-# INLINEABLE parseJSON #-}

{- | Construct a policy from a collection of 'NonEmpty' 'Statement's using the
 default @2012-10-17@ version and no identifier.

==== Example

>>> encode' $ document (pure allow <> pure deny)
{
    "Statement": [
        {
            "Effect": "Allow",
            "Action": []
        },
        {
            "Effect": "Deny",
            "Action": []
        }
    ],
    "Version": "2012-10-17"
}

-}
document :: NonEmpty a -> Policy a
document xs = Policy
    { version   = Just Version_2012_10_17
    , id        = Nothing
    , statement = xs
    }
{-# INLINEABLE document #-}

{- | Construct a policy from a single 'Statement' using the default
@2012-10-17@ version and no identifier.

==== Example

>>> encode' $ singleton (allow { resource = any })
{
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [],
            "Resource": "*"
        }
    ],
    "Version": "2012-10-17"
}

-}
singleton :: a -> Policy a
singleton = document . pure
{-# INLINEABLE singleton #-}

{- | Encode the IAM policy document as JSON.

==== Example

>>> encode $ singleton allow
"{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[]}],\"Version\":\"2012-10-17\"}"

-}
encode :: Policy Statement -> LBS.ByteString
encode = JSON.encode
{-# INLINEABLE encode #-}

{- | The 'Version' elements specifies the language syntax rules that are to be
used to process this policy. If you include features that are not available in
the specified version, then your policy will generate errors or not work the
way you intend. As a general rule, you should specify the most recent version
available, unless you depend on a feature that was deprecated in later
versions.

==== Grammar

> <version_block> = "Version" : ("2008-10-17" | "2012-10-17")

==== Example

>>> JSON.encode Version_2012_10_17
"\"2012-10-17\""

-}
data Version
    = Version_2008_10_17
    | Version_2012_10_17
      deriving (Show, Eq, Ord, Generic)

instance Hashable Version

-- | '(<>)' always chooses the newest version.
instance Semigroup Version where
    (<>) = max
    {-# INLINEABLE (<>) #-}

instance ToJSON Version where
    toJSON = \case
        Version_2008_10_17 -> JSON.String "2008-10-17"
        Version_2012_10_17 -> JSON.String "2012-10-17"
    {-# INLINEABLE toJSON #-}

instance FromJSON Version where
    parseJSON = JSON.withText "Version" $ \case
        "2008-10-17" -> pure Version_2008_10_17
        "2012-10-17" -> pure Version_2012_10_17
        x            -> fail ("Unabled to parse Version from " ++ show x)
    {-# INLINEABLE parseJSON #-}

{- | The 'Id' element specifies an optional identifier for the policy. The ID
is used differently in different services.

For services that let you set an ID element, we recommend you use a UUID
(GUID) for the value, or incorporate a UUID as part of the ID to ensure
uniqueness.

/Note/: Some AWS services (for example, Amazon SQS or Amazon SNS) might
require this element and have uniqueness requirements for it. For
service-specific information about writing policies, refer to the
documentation for the service you're working with.

Use the 'id' record field to set the 'Id' of a 'Policy' document.

==== Grammar

> <id_block> = "Id" : <policy_id_string>

==== Example

>>> encode' $ (singleton allow) { id = Just "123" }
{
...
    "Id": "123"
}

-}
newtype Id = Id { fromId :: Text }
    deriving (Show, Eq, Ord, Hashable, ToJSON, FromJSON, IsString)

{- | The 'Statement' element is the main element for a policy. This element is
required. It can include multiple elements (see the subsequent sections in this
page). The Statement element contains an array of individual statements.

==== Grammar

> <statement_block> = "Statement" : [ <statement>, <statement>, ... ]
>
> <statement> = {
>     <sid_block?>,
>     <principal_block?>,
>     <effect_block>,
>     <action_block>,
>     <resource_block>,
>     <condition_block?>
> }

-}
data Statement = Statement
    { sid       :: !(Maybe Sid)
    , principal :: !(Maybe (Block Principal))
    , effect    :: !Effect
    , action    :: !(Block [Action])
    , resource  :: !(Block [Resource])
    , condition :: !(Maybe Condition)
    } deriving (Show, Eq, Ord, Generic)

instance Hashable Statement

instance ToJSON Statement where
    toJSON Statement{..} =
        let oneOrMany = fmap (fromList :: [a] -> OneOrMany a)
         in JSON.object $ catMaybes
            [ fmap ("Sid" .=) sid
            , fmap (blockToJSON "Principal") principal
            , Just ("Effect" .= effect)
            , Just (blockToJSON "Action"   $ oneOrMany action)
            , fmap (blockToJSON "Resource" . oneOrMany . fmap NE.toList)
                   (sequence (fmap NE.nonEmpty resource))
            , fmap ("Condition" .=) condition
            ]
    {-# INLINEABLE toJSON #-}

instance FromJSON Statement where
    parseJSON = JSON.withObject "Statement" $ \o -> do
        sid       <- o .:? "Sid"
        principal <- optional (blockParseJSON "Principal" o)
        effect    <- o .:  "Effect"
        action    <- oneOrMany <$> blockParseJSON "Action"   o
        resource  <- oneOrMany <$> blockParseJSON "Resource" o
        condition <- o .:? "Condition"
        pure Statement{..}
      where
        oneOrMany = fmap (toList :: OneOrMany a -> [a])
    {-# INLINEABLE parseJSON #-}

-- | Create a new statement with the effect set to 'Allow'.
allow :: Statement
allow = Statement
    { sid       = Nothing
    , principal = Nothing
    , effect    = Allow
    , action    = Match mempty
    , resource  = Match mempty
    , condition = Nothing
    }
{-# INLINEABLE allow #-}

-- | Create a new statement with the effect set to 'Deny'.
deny :: Statement
deny = allow { effect = Deny }
{-# INLINEABLE deny #-}

{- | The 'Sid' (statement ID) is an optional identifier that you provide for the
policy statement. You can assign a Sid value to each statement in a statement
array. In services that let you specify an ID element, such as SQS and SNS, the
Sid value is just a sub-ID of the policy document's ID. In IAM, the Sid value
must be unique within a JSON policy.

In IAM, the Sid is not exposed in the IAM API. You can't retrieve a
particular statement based on this ID.

/Note/: Some AWS services (for example, Amazon SQS or Amazon SNS) might require this
element and have uniqueness requirements for it. For service-specific
information about writing policies, refer to the documentation for the service
you're working with.

Use the 'sid' record field to set the 'Sid' of a 'Statement'.

==== Grammar

> <sid_block> = "Sid" : <sid_string>

==== Example

>>> encode' $ singleton (allow { sid = Just "cd3ad3d9-2776-4ef1-a904-4c229d1642ee" })
{
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [],
            "Sid": "cd3ad3d9-2776-4ef1-a904-4c229d1642ee"
        }
    ],
    "Version": "2012-10-17"
}

-}
newtype Sid = Sid { fromSid :: Text }
    deriving (Show, Eq, Ord, Hashable, ToJSON, FromJSON, IsString)

{- | The 'Effect' element is required and specifies whether the statement
results in an allow or an explicit deny.

By default, access to resources is denied. To allow access to a resource,
you must set the Effect element to 'Allow'. To override an allow (for example,
to override an allow that is otherwise in force), you set the Effect element
to 'Deny'.

See the 'allow' and 'deny' smart constructors to create a 'Statement' with the
desired 'Effect' set.

==== Grammar

> <effect_block> = "Effect" : ("Allow" | "Deny")
-}
data Effect = Allow | Deny
    deriving (Show, Eq, Ord, Generic, Enum)

instance Hashable Effect

instance ToJSON Effect where
    toJSON = \case
        Allow -> "Allow"
        Deny  -> "Deny"
    {-# INLINEABLE toJSON #-}

instance FromJSON Effect where
    parseJSON = JSON.withText "Effect" $ \case
        "Allow" -> pure Allow
        "Deny"  -> pure Deny
        x       -> fail ("Unabled to parse Effect from " ++ show x)
    {-# INLINEABLE parseJSON #-}

{- | Use the 'Principal' element to specify the user (IAM user, federated user, or
assumed-role user), AWS account, AWS service, or other principal entity that
is allowed or denied access to a resource. You use the Principal element in
the trust policies for IAM roles and in resource-based policies—that is, in
policies that you embed directly in a resource. For example, you can embed
such policies in an Amazon S3 bucket, an Amazon Glacier vault, an Amazon SNS
topic, an Amazon SQS queue, or an AWS KMS customer master key (CMK).

Use the Principal element in these ways:

In IAM roles, use the Principal element in the role's trust policy to
specify who can assume the role. For cross-account access, you must specify
the 12-digit identifier of the trusted account.

/Note/: After you create the role, you can change the account to "*" to
allow everyone to assume the role. If you do this, we strongly recommend
that you limit who can access the role through other means, such as a
Condition element that limits access to only certain IP addresses. Do not
leave your role accessible to everyone!

In resource-based policies, use the 'Principal' element to specify the
accounts or users who are allowed to access the resource.

You can use 'Not' to negate the meaning of a 'Principal' element.

==== Grammar

> <principal_block> = ("Principal" | "NotPrincipal") : ("*" | <principal_map>)
>
> <principal_map> = { <principal_map_entry>, <principal_map_entry>, ... }
>
> <principal_map_entry> = ("AWS" | "Federated" | "Service") :
>     [<principal_id_string>, <principal_id_string>, ...]

==== Example

>>> encode' $ singleton (allow { principal = Just $ not Everyone })
{
    "Statement": [
        {
            "Effect": "Allow",
            "NotPrincipal": "*",
            "Action": []
        }
    ],
    "Version": "2012-10-17"
}

>>> encode' $ singleton (allow { principal = Just $ some (AWS (pure "arn:foo:::bar")) })
{
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [],
            "Principal": {
                "AWS": [
                    "arn:foo:::bar"
                ]
            }
        }
    ],
    "Version": "2012-10-17"
}

-}
data Principal
    = Everyone
    | AWS           !(NonEmpty Text)
    | Federated     !Text
    | Service       !(NonEmpty Text)
    | CanonicalUser !Text
      deriving (Show, Eq, Ord, Generic)

instance Hashable Principal

instance ToJSON Principal where
    toJSON = \case
        Everyone         -> JSON.String "*"
        AWS           ks -> JSON.object ["AWS"           .= ks]
        Federated     k  -> JSON.object ["Federated"     .= k]
        Service       ks -> JSON.object ["Service"       .= ks]
        CanonicalUser k  -> JSON.object ["CanonicalUser" .= k]
    {-# INLINEABLE toJSON #-}

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
    {-# INLINEABLE parseJSON #-}

{- | The 'Action' element describes the specific action or actions that will be
allowed or denied. Statements must include either an Action or NotAction
element. Each AWS service has its own set of actions that describe tasks that
you can perform with that service.

You can use 'Not' to negate the meaning of a list of 'Action' elements.

==== Grammar

> <action_block> = ("Action" | "NotAction") :
>     ("*" | [<action_string>, <action_string>, ...])

-}
newtype Action = Action { fromAction :: Text }
    deriving (Show, Eq, Ord, Hashable, ToJSON, FromJSON, IsString)

{- | The 'Resource' element specifies the object or objects that the statement
covers. Statements must include either a Resource or a NotResource element.

Each service has its own set of resources. Although you always use an ARN to
specify a resource, the details of the ARN for a resource depend on the
service and the resource. For information about how to specify a resource,
refer to the documentation for the service whose resources you're writing a
statement for.

/Note:/ Some services do not let you specify actions for individual
resources; instead, any actions that you list in the Action or NotAction
element apply to all resources in that service. In these cases, you use the
wildcard @"*"@ in the Resource element.

You can use 'Not' to negate the meaning of a list of 'Resource' elements.

==== Grammar

> <resource_block> = ("Resource" | "NotResource") :
>     ("*" | [<resource_string>, <resource_string>, ...])

-}
newtype Resource = Resource { fromResource :: Text }
    deriving (Show, Eq, Ord, Hashable, ToJSON, FromJSON, IsString)

-- | A key that will be tested as the target of a 'Condition'.
newtype Key = Key { fromKey :: Text }
    deriving (Show, Eq, Ord, Hashable, FromJSON, ToJSON, IsString)

{- | The 'Condition' element (or Condition block) lets you specify conditions
for when a policy is in effect. The Condition element is optional. In the
Condition element, you build expressions in which you use condition operators
(equal, less than, etc.) to match the condition in the policy against values in
the request. Condition values can include date, time, the IP address of the
requester, the ARN of the request source, the user name, user ID, and the user
agent of the requester. Some services let you specify additional values in
conditions; for example, Amazon S3 lets you write a condition using the
@s3:VersionId@ key, which is unique to that service.

    * __String:__
      String condition operators let you construct 'Condition' elements that
      restrict access based on comparing a key to a string value.

    * __Numeric:__
      Numeric condition operators let you construct Condition elements that
      restrict access based on comparing a key to an integer or decimal value.

    * __Date:__
      Date condition operators let you construct Condition elements that restrict
      access based on comparing a key to a date/time value. You use these condition
      operators with the aws:CurrentTime key or aws:EpochTime keys. You must specify
      date/time values with one of the W3C implementations of the ISO 8601 date
      formats or in epoch (UNIX) time.
      Wildcards are not permitted for date condition operators.

    * __Boolean:__
      Boolean conditions let you construct Condition elements that restrict access
      based on comparing a key to "true" or "false."

    * __Binary:__
      The BinaryEquals condition operator let you construct Condition elements
      that test key values that are in binary format. It compares the value of the
      specified key byte for byte against a base-64 encoded representation of the
      binary value in the policy.

    * __IP Address:__
      IP address condition operators let you construct Condition elements that
      restrict access based on comparing a key to an IPv4 or IPv6 address or range
      of IP addresses. You use these with the aws:SourceIp key. The value must be
      in the standard CIDR format (for example, 203.0.113.0/24 or
      2001:DB8:1234:5678::/64). If you specify an IP address without the
      associated routing prefix, IAM uses the default prefix value of /32.
      Some AWS services support IPv6, using :: to represent a range of 0s. To
      learn whether a service supports IPv6, see the documentation for that
      service.

    * __Amazon Resource Name (ARN):__
      Amazon Resource Name (ARN) condition operators let you construct Condition
      elements that restrict access based on comparing a key to an ARN. The ARN is
      considered a string. This value is available for only some services; not all
      services support request values that can be compared as ARNs.

    * __Key Existence:__
      You can add IfExists to the end of any condition operator name except the
      Null condition—for example, StringLikeIfExists. You do this to say "If the
      policy key is present in the context of the request, process the key as
      specified in the policy. If the key is not present, the condition evaluate
      the condition element as true." Other condition elements in the statement
      can still result in a nonmatch, but not a missing key when checked with
      ...IfExists.

    * __Null:__
      Use a Null condition operator to check if a condition key is present at the
      time of authorization. In the policy statement, use either true (the key
      doesn't exist — it is null) or false (the key exists and its value is not null).
      For example, you can use this condition operator to determine whether a user is
      using their own credentials for the operation or temporary credentials. If the
      user is using temporary credentials, then the key aws:TokenIssueTime exists and
      has a value. The following example shows a condition that states that the user
      must not be using temporary credentials (the key must not exist) for the user
      to use the Amazon EC2 API.

==== Grammar

> <condition_block> = "Condition" : { <condition_map> }
>
> <condition_map> {
>   <condition_type_string> : { <condition_key_string> : <condition_value_list> },
>   <condition_type_string> : { <condition_key_string> : <condition_value_list> }, ...
> }
>
> <condition_value_list> = [<condition_value>, <condition_value>, ...]
>
> <condition_value> = ("string" | "number" | "Boolean")

==== Example

>>> encode' $ singleton (allow { condition = Just (Bool "aws:MultiFactorAuthPresent" True) })
{
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [],
            "Condition": {
                "Bool": {
                    "aws:MultiFactorAuthPresent": true
                }
            }
        }
    ],
    "Version": "2012-10-17"
}

-}
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
      deriving (Show, Eq, Ord, Generic)

instance Hashable Condition where
    hashWithSalt s = \case
        StringEquals k v ->
            s `hashWithSalt` (0 :: Int)
              `hashWithSalt` k
              `hashWithSalt` v
        StringNotEquals k v ->
            s `hashWithSalt` (1 :: Int)
              `hashWithSalt` k
              `hashWithSalt` v
        StringEqualsIgnoreCase k v ->
            s `hashWithSalt` (2 :: Int)
              `hashWithSalt` k
              `hashWithSalt` v
        StringNotEqualsIgnoreCase k v ->
            s `hashWithSalt` (3 :: Int)
              `hashWithSalt` k
              `hashWithSalt` v
        StringLike k vs ->
            s `hashWithSalt` (4 :: Int)
              `hashWithSalt` k
              `hashWithSalt` vs
        StringNotLike k vs ->
            s `hashWithSalt` (5 :: Int)
              `hashWithSalt` k
              `hashWithSalt` vs

        NumericEquals k v ->
            s `hashWithSalt` (6 :: Int)
              `hashWithSalt` k
              `hashWithSalt` v
        NumericNotEquals k v ->
            s `hashWithSalt` (7 :: Int)
              `hashWithSalt` k
              `hashWithSalt` v
        NumericLessThan k v ->
            s `hashWithSalt` (8 :: Int)
              `hashWithSalt` k
              `hashWithSalt` v
        NumericLessThanEquals k v ->
            s `hashWithSalt` (9 :: Int)
              `hashWithSalt` k
              `hashWithSalt` v
        NumericGreaterThan k v ->
            s `hashWithSalt` (10 :: Int)
              `hashWithSalt` k
              `hashWithSalt` v
        NumericGreaterThanEquals k v ->
            s `hashWithSalt` (11 :: Int)
              `hashWithSalt` k
              `hashWithSalt` v

        DateEquals k v ->
            s `hashWithSalt` (12 :: Int)
              `hashWithSalt` k
              `hashUTCTime`  v
        DateNotEquals k v ->
            s `hashWithSalt` (13 :: Int)
              `hashWithSalt` k
              `hashUTCTime`  v
        DateLessThan k v ->
            s `hashWithSalt` (14 :: Int)
              `hashWithSalt` k
              `hashUTCTime`  v
        DateLessThanEquals k v ->
            s `hashWithSalt` (15 :: Int)
              `hashWithSalt` k
              `hashUTCTime`  v
        DateGreaterThan k v ->
            s `hashWithSalt` (16 :: Int)
              `hashWithSalt` k
              `hashUTCTime`  v
        DateGreaterThanEquals k v ->
            s `hashWithSalt` (17 :: Int)
              `hashWithSalt` k
              `hashUTCTime`  v

        Bool k v ->
            s `hashWithSalt` (18 :: Int)
              `hashWithSalt` k
              `hashWithSalt` v

        BinaryEquals k v ->
            s `hashWithSalt` (19 :: Int)
              `hashWithSalt` k
              `hashWithSalt` v

        IpAddress k v ->
            s `hashWithSalt` (20 :: Int)
              `hashWithSalt` k
              `hashWithSalt` v
        NotIpAddress k v ->
            s `hashWithSalt` (21 :: Int)
              `hashWithSalt` k
              `hashWithSalt` v

        ArnEquals k v ->
            s `hashWithSalt` (22 :: Int)
              `hashWithSalt` k
              `hashWithSalt` v
        ArnLike k v ->
            s `hashWithSalt` (23 :: Int)
              `hashWithSalt` k
              `hashWithSalt` v
        ArnNotEquals k v ->
            s `hashWithSalt` (24 :: Int)
              `hashWithSalt` k
              `hashWithSalt` v
        ArnNotLike k v ->
            s `hashWithSalt` (25 :: Int)
              `hashWithSalt` k
              `hashWithSalt` v
    {-# INLINEABLE hashWithSalt #-}

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
    {-# INLINEABLE toJSON #-}

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
    {-# INLINEABLE parseJSON #-}

infixl 0 `hashUTCTime`

hashUTCTime :: Int -> UTCTime -> Int
hashUTCTime s (Time.UTCTime (Time.ModifiedJulianDay day) diff) =
    s `hashWithSalt` day
      `hashWithSalt` (Time.diffTimeToPicoseconds diff)
