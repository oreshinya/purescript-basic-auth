module Node.BasicAuth
  ( Credentials
  , authenticate
  ) where

import Prelude

import Control.Monad.Maybe.Trans (MaybeT(..), runMaybeT)
import Data.Array.NonEmpty ((!!))
import Data.Maybe (Maybe(..))
import Data.String.Regex (Regex, match)
import Data.String.Regex.Flags (noFlags)
import Data.String.Regex.Unsafe (unsafeRegex)
import Effect (Effect)
import Effect.Class (liftEffect)
import Foreign.Object (lookup)
import Node.Buffer (Buffer, fromString, toString)
import Node.Crypto (timingSafeEqualString)
import Node.Encoding (Encoding(..))
import Node.HTTP (Request, requestHeaders)

type Credentials =
  { user :: String
  , pass :: String
  }

authenticate :: Credentials -> Request -> Effect Boolean
authenticate cred req = do
  result <- runMaybeT parse
  case result of
    Nothing -> pure false
    Just r ->
      conj
        <$> timingSafeEqualString cred.user r.user
        <*> timingSafeEqualString cred.pass r.pass
  where
    parse = do
      token <- MaybeT $ pure
        $ getAuthorization req
        >>= match credentialsRegex
        >>= (_ !! 1) >>> join
      decoded <- liftEffect
        $ (fromString token Base64 :: Effect Buffer)
        >>= toString UTF8
      ms <- MaybeT $ pure $ match userPassRegex decoded
      MaybeT $ pure $ { user: _, pass: _ }
        <$> (join $ ms !! 1)
        <*> (join $ ms !! 2)

getAuthorization :: Request -> Maybe String
getAuthorization req = lookup "authorization" $ requestHeaders req

credentialsRegex :: Regex
credentialsRegex = unsafeRegex "^ *(?:[Bb][Aa][Ss][Ii][Cc]) +([A-Za-z0-9._~+/-]+=*) *$" noFlags

userPassRegex :: Regex
userPassRegex = unsafeRegex "^([^:]*):(.*)$" noFlags
