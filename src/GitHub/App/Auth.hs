{- This Source Code Form is subject to the terms of the Mozilla Public
 - License, v. 2.0. If a copy of the MPL was not distributed with this
 - file, You can obtain one at http://mozilla.org/MPL/2.0/.
 -}

{-# LANGUAGE CPP       #-}
{-# LANGUAGE DataKinds #-}

module GitHub.App.Auth
       ( AppAuth

       , InstallationAuth
       , mkInstallationAuth

       , obtainAccessToken
       ) where

import Prelude hiding (exp)

import Control.Concurrent (MVar, newMVar, putMVar, readMVar, takeMVar)
import Control.Exception.Safe (bracketOnError, catch)
import Control.Monad.Except (ExceptT, MonadError (throwError), runExceptT)
import Control.Monad.Trans (lift)
import Crypto.Types.PubKey.RSA (PrivateKey)
import Data.Aeson (FromJSON (..), withObject, (.:))
import qualified Data.ByteString.Lazy as LBS
import Data.Functor (($>))
import Data.Maybe (fromMaybe)
import Data.Semigroup ((<>))
import Data.Text (Text)
import qualified Data.Text as T
import Data.Text.Encoding (encodeUtf8)
import Data.Time (NominalDiffTime, UTCTime, diffUTCTime, getCurrentTime)
import Data.Time.Clock.POSIX (utcTimeToPOSIXSeconds)
import GitHub.Auth (Auth (OAuth))
import GitHub.Data.Apps (App)
import GitHub.Data.Definitions (Error (HTTPError))
import GitHub.Data.Id (Id, untagId)
import GitHub.Data.Installations (Installation)
import GitHub.Data.Request (StatusMap)
import GitHub.Request (parseResponse)
import Network.HTTP.Client as HTTP
import qualified Network.HTTP.Client.Internal as HTTP
import qualified Network.HTTP.Types as HTTP
import Web.JWT (JWTClaimsSet (exp, iat, iss), Signer (RSAPrivateKey), encodeSigned, numericDate,
                stringOrURI)


-- | JWT expiration time. Maximum accepted by GitHub is 10 minutes
jwtExpTime :: NominalDiffTime
jwtExpTime = 600

-- | Installation access token expiration time. It is fixed by GitHub and is equal to 1 hour
instKeyExpTime :: NominalDiffTime
instKeyExpTime = 3600

-- | When to renew the installation access token
--
-- We renew the access token when it is valid for less than 'bufferTime'
-- just to be on the safe side.
bufferTime :: NominalDiffTime
bufferTime = instKeyExpTime * 0.25

baseUrl :: Text
baseUrl = "https://api.github.com"


-- | Credentials of a GitHub App
data AppAuth = AppAuth
    { aaAppId      :: !(Id App)
    , aaPrivateKey :: !PrivateKey
    }

-- | Cached GitHub installation access token
data InstallationToken = InstallationToken
    { itToken          :: !Auth
    , itExpirationTime :: !UTCTime
    } deriving (Show)

instance FromJSON InstallationToken where
    parseJSON = withObject "Installation access token" $ \o ->
        InstallationToken
            <$> (OAuth . encodeUtf8 <$> o .: "token")
            <*> o .: "expires_at"


-- | Credentials required for an App to authenticate as an installation
data InstallationAuth = InstallationAuth
    { iaClaimsSet      :: !JWTClaimsSet                      -- ^ Prefilled claims set
    , iaAppPrivateKey  :: !PrivateKey                        -- ^ Private key to sign token requests
    , iaInstallationId :: !Text                              -- ^ Installation id
    , iaToken          :: !(MVar (Maybe InstallationToken))  -- ^ Installation Auth token
    }


-- | Smart constructor for 'InstallationAuth'
mkInstallationAuth
    :: AppAuth
    -> Id Installation
    -> IO InstallationAuth
mkInstallationAuth AppAuth{aaAppId, aaPrivateKey} instId = do
    varToken <- newMVar Nothing
    let issuer = fromMaybe (error "impossible") . stringOrURI . T.pack . show . untagId $ aaAppId
        claimsSet = mempty { iss = Just issuer }
    pure $ InstallationAuth claimsSet aaPrivateKey (T.pack . show . untagId $ instId) varToken

-- | Create a request which, when executed, will obtain a new access token
createAccessTokenR :: InstallationAuth -> IO HTTP.Request
createAccessTokenR InstallationAuth{..} = do
    currentTime <- utcTimeToPOSIXSeconds <$> getCurrentTime
    let expiryTime = currentTime + jwtExpTime
        claims = iaClaimsSet
            { iat = Just $ toJsonTime currentTime
            , exp = Just $ toJsonTime expiryTime
            }
        jwt = encodeSigned (RSAPrivateKey iaAppPrivateKey) claims

    req <- HTTP.parseRequest . T.unpack $ url
    pure req
        { HTTP.requestHeaders = [("Authorization", "Bearer " <> encodeUtf8 jwt)]
        , HTTP.checkResponse = successOrMissing Nothing
        , HTTP.method = "POST"
        }
  where
    toJsonTime = fromMaybe (error "impossible") . numericDate
    url = baseUrl <> "/installations/" <> iaInstallationId <> "/access_tokens"

-- | Get a valid access token
--
-- Tries to use the cached one. If it is invalid, requests a new one
-- and caches it for future use.
obtainAccessToken
    :: Manager
    -> InstallationAuth
    -> IO (Either Error Auth)
obtainAccessToken mgr ia@InstallationAuth{..} = readMVar iaToken >>= \case
    Nothing -> renew
    Just InstallationToken{itToken, itExpirationTime} -> do
        currentTime <- getCurrentTime
        if itExpirationTime `diffUTCTime` currentTime < bufferTime
        then renew
        else pure $ Right itToken
  where
    renew :: IO (Either Error Auth)
    renew = bracketOnError (takeMVar iaToken) (putMVar iaToken) $ \_ -> do
        req <- createAccessTokenR ia
        result <- runExceptT $ httpLbs' req >>= parseResponse
        case result of
            Right newToken -> putMVar iaToken (Just newToken) $> Right (itToken newToken)
            Left  err      -> putMVar iaToken Nothing $> Left err

    httpLbs' :: HTTP.Request -> ExceptT Error IO (Response LBS.ByteString)
    httpLbs' req' = lift (httpLbs req' mgr) `catch` onHttpException



---------------------------------------
-- Copy-pasted from the github package
---------------------------------------

#if MIN_VERSION_http_client(0,5,0)
successOrMissing :: Maybe (StatusMap a) -> HTTP.Request -> HTTP.Response HTTP.BodyReader -> IO ()
successOrMissing sm _req res
    | check     = pure ()
    | otherwise = do
        chunk <- HTTP.brReadSome (HTTP.responseBody res) 1024
        let res' = fmap (const ()) res
        HTTP.throwHttp $ HTTP.StatusCodeException res' (LBS.toStrict chunk)
  where
    HTTP.Status sci _ = HTTP.responseStatus res
#else
successOrMissing :: Maybe (StatusMap a) -> Status -> ResponseHeaders -> HTTP.CookieJar -> Maybe E.SomeException
successOrMissing sm s@(Status sci _) hs cookiejar
    | check     = Nothing
    | otherwise = Just $ E.toException $ StatusCodeException s hs cookiejar
  where
#endif
    check = case sm of
      Nothing  -> 200 <= sci && sci < 300
      Just sm' -> sci `elem` map fst sm'

onHttpException :: MonadError Error m => HttpException -> m a
onHttpException = throwError . HTTPError
