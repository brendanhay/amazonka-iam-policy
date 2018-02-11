{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE RankNTypes #-}

-- | This module contains lenses and prisms that can be used with any of the
-- various lens libraries. It's recommended that you import this module
-- qualified to avoid ambiguity with "Amazonka.IAM.Policy":
--
-- @
-- import qualified Amazonka.IAM.Policy.Lens as Lens
-- @
module Amazonka.IAM.Policy.Lens
    (
    -- * Lenses

    -- ** Policy
      version
    , id
    , statement

    -- ** Statement
    , sid
    , effect
    , principal
    , action
    , resource
    , condition

    -- * Prisms

    -- ** Block
    , _Match
    , _Not

    -- ** Match
    , _Some
    , _Wildcard
    ) where

import Prelude hiding (id)

import Data.List.NonEmpty     (NonEmpty)
import Data.Profunctor        (dimap)
import Data.Profunctor.Choice (Choice (right'))

import Amazonka.IAM.Policy (Action, Block (..), Condition, Effect, Id,
                            Match (..), Policy, Principal, Resource, Sid,
                            Statement, Version)

import qualified Amazonka.IAM.Policy as Policy

-- Lenses

type Lens s t a b = forall f. Functor f => (a -> f b) -> s -> f t

type Lens' s a = Lens s s a a

id :: Lens' (Policy a) (Maybe Id)
id f s = (\a -> s { Policy.id = a }) <$> f (Policy.id s)
{-# INLINEABLE id #-}

version :: Lens' (Policy a) (Maybe Version)
version f s = (\a -> s { Policy.version = a }) <$> f (Policy.version s)
{-# INLINEABLE version #-}

statement :: Lens (Policy a) (Policy b) (NonEmpty a) (NonEmpty b)
statement f s = (\a -> s { Policy.statement = a }) <$> f (Policy.statement s)
{-# INLINEABLE statement #-}

sid :: Lens' Statement (Maybe Sid)
sid f s = (\a -> s { Policy.sid = a }) <$> f (Policy.sid s)
{-# INLINEABLE sid #-}

principal :: Lens' Statement (Maybe (Block Principal))
principal f s = (\a -> s { Policy.principal = a }) <$> f (Policy.principal s)
{-# INLINEABLE principal #-}

effect :: Lens' Statement Effect
effect f s = (\a -> s { Policy.effect = a }) <$> f (Policy.effect s)
{-# INLINEABLE effect #-}

action :: Lens' Statement (Block [Action])
action f s = (\a -> s { Policy.action = a }) <$> f (Policy.action s)
{-# INLINEABLE action #-}

resource :: Lens' Statement (Block [Resource])
resource f s = (\a -> s { Policy.resource = a }) <$> f (Policy.resource s)
{-# INLINEABLE resource #-}

condition :: Lens' Statement (Maybe Condition)
condition f s = (\a -> s { Policy.condition = a }) <$> f (Policy.condition s)
{-# INLINEABLE condition #-}

-- Prisms

type Prism s t a b = forall p f. (Choice p, Applicative f) => p a (f b) -> p s (f t)

prism :: (b -> t) -> (s -> Either t a) -> Prism s t a b
prism bt seta = dimap seta (either pure (fmap bt)) . right'
{-# INLINE prism #-}

_Match :: Prism (Block a) (Block a) (Match a) (Match a)
_Match =
    prism Match $ \case
        Match x -> Right x
        y       -> Left  y
{-# INLINEABLE _Match #-}

_Not :: Prism (Block a) (Block a) (Match a) (Match a)
_Not =
    prism Not $ \case
        Not x -> Right x
        y     -> Left  y
{-# INLINEABLE _Not #-}

_Some :: Prism (Match a) (Match b) a b
_Some =
    prism Some $ \case
        Some   x -> Right x
        Wildcard -> Left  Wildcard
{-# INLINE _Some #-}

_Wildcard :: Prism (Match a) (Match a) () a
_Wildcard =
    prism (const Wildcard) $ \case
        Wildcard -> Right ()
        Some x   -> Left  (Some x)
{-# INLINE _Wildcard #-}
