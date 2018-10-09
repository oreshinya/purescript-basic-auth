module Node.BasicAuth
  ( User
  , Password
  , authenticate
  ) where

import Prelude

import Data.Array.NonEmpty ((!!))
import Data.Maybe (Maybe(..))
import Data.String.Regex (Regex, match)
import Data.String.Regex.Flags (noFlags)
import Data.String.Regex.Unsafe (unsafeRegex)
import Effect (Effect)
import Foreign.Object (lookup)
import Node.Buffer (fromString, toString)
import Node.Crypto (timingSafeEqualString)
import Node.Encoding (Encoding(..))
import Node.HTTP (Request, requestHeaders)



type User = String

type Password = String

type Credentials =
  { user :: User
  , pass :: Password
  }



authenticate :: User -> Password -> Request -> Effect Boolean
authenticate user pass req =
  case getAuthorization req of
    Nothing -> pure false
    Just h -> do
       mCred <- parse h
       case mCred of
         Nothing -> pure false
         Just cred ->
           conj <$> timingSafeEqualString user cred.user <*> timingSafeEqualString pass cred.pass



getAuthorization :: Request -> Maybe String
getAuthorization req = lookup "authorization" $ requestHeaders req



parse :: String -> Effect (Maybe Credentials)
parse x =
  case match credentialsRegex x of
    Just ms ->
      case ms !! 1 of
        Just (Just token) -> do
          decoded <- fromString token Base64 >>= toString UTF8
          case match userPassRegex decoded of
            Just ms' ->
              case ms' !! 1, ms' !! 2 of
                Just (Just user), Just (Just pass) ->
                  pure $ Just { user, pass }
                _, _ -> pure Nothing
            _ -> pure Nothing
        _ -> pure Nothing
    _ -> pure Nothing



credentialsRegex :: Regex
credentialsRegex = unsafeRegex "^ *(?:[Bb][Aa][Ss][Ii][Cc]) +([A-Za-z0-9._~+/-]+=*) *$" noFlags



userPassRegex :: Regex
userPassRegex = unsafeRegex "^([^:]*):(.*)$" noFlags
