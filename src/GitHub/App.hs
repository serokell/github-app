{- This Source Code Form is subject to the terms of the Mozilla Public
 - License, v. 2.0. If a copy of the MPL was not distributed with this
 - file, You can obtain one at http://mozilla.org/MPL/2.0/.
 -}

module GitHub.App
       ( InstallationAuth
       , mkInstallationAuth

       , authenticateInstallation
       ) where

import Prelude hiding (exp)

import Control.Concurrent (MVar, newEmptyMVar, putMVar, readMVar, takeMVar)
import Control.Monad (void)
import Crypto.Types.PubKey.RSA (PrivateKey (..))
import Data.Aeson (FromJSON (..), withObject, (.:))
import Data.ByteString (ByteString)
import Data.Default.Class (def)
import Data.Semigroup ((<>))
import Data.Text (Text)
import qualified Data.Text as T
import Data.Text.Encoding (encodeUtf8)
import Data.Time (NominalDiffTime, UTCTime, addUTCTime, defaultTimeLocale, diffUTCTime,
                  getCurrentTime, iso8601DateFormat, parseTimeM)
import Data.Time.Clock.POSIX (utcTimeToPOSIXSeconds)
import GitHub.Auth (Auth (..))
import Network.HTTP.Req (NoReqBody (..), Option, POST (..), Url, header, https, jsonResponse, req,
                         responseBody, runReq, (/:))
import Web.JWT (JSON, JWTClaimsSet (..), Signer (..), encodeSigned, numericDate, stringOrURI)


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


-- | Base URL of the GitHub API
baseURL :: Text
baseURL = "api.github.com"


type InstallationId = Text


-- | GitHub installation access token
data InstallationToken = InstallationToken
    { itToken          :: ByteString
    , itExpirationTime :: UTCTime
    } deriving (Show)

instance FromJSON InstallationToken where
    parseJSON = withObject "installation token" $ \o -> InstallationToken
        <$> (encodeUtf8 <$> o .: "token")
        <*> (either fail pure =<< parseExpiresAt <$> o .: "expires_at")
      where
        parseExpiresAt :: String -> Either String UTCTime
        parseExpiresAt = parseTimeM True defaultTimeLocale (iso8601DateFormat (Just "%H:%M:%SZ"))

-- | Credentials required for an app to authenticate as an installation
data InstallationAuth = InstallationAuth
    { iaAppId          :: !Int                       -- ^ Application id
    , iaAppPrivateKey  :: !PrivateKey                -- ^ Private key to sign token requests
    , iaInstallationId :: !Text                      -- ^ Installation id
    , iaToken          :: !(MVar InstallationToken)  -- ^ Installation Auth token
    }

-- | Return a valid App access token
--
-- Checks if the cached token is expired and renews it if needed.
authenticateInstallation :: InstallationAuth -> IO Auth
authenticateInstallation ia@InstallationAuth{iaToken} = do
    InstallationToken{itToken, itExpirationTime} <- readMVar iaToken
    currentTime <- getCurrentTime
    if itExpirationTime `diffUTCTime` currentTime >= bufferTime
    then return $ OAuth itToken
    else do
        void $ takeMVar iaToken
        renewInstAuthToken ia
        InstallationToken{itToken = newToken} <- readMVar iaToken
        return $ OAuth newToken

-- | Smart constructor for 'InstallationAuth'
mkInstallationAuth :: Int -> PrivateKey -> InstallationId -> IO InstallationAuth
mkInstallationAuth applicationId key instId = do
    tokenVar  <- newEmptyMVar
    let instAuth = InstallationAuth applicationId key instId tokenVar
    renewInstAuthToken instAuth
    return instAuth

-- | Get a new token from GitHub and cache it in 'InstallationAuth'
--
-- Assumes that the MVar in 'InstallationAuth' is empty. Otherwise will block.
renewInstAuthToken :: InstallationAuth -> IO ()
renewInstAuthToken InstallationAuth{iaAppId, iaInstallationId, iaAppPrivateKey, iaToken} = do
    time <- getCurrentTime
    let jwt = makeJWT time
    t <- request (https baseURL /: "installations" /: iaInstallationId /: "access_tokens") mempty jwt
    putMVar iaToken t
  where
    -- | Create a JSON Web Token for the given application id using application's private key
    makeJWT :: UTCTime -> JSON
    makeJWT currentTime =
      let currDate     = numericDate . utcTimeToPOSIXSeconds $ currentTime
          expDate      = numericDate . utcTimeToPOSIXSeconds $ jwtExpTime `addUTCTime` currentTime
          issuer       = stringOrURI . T.pack . show $ iaAppId
          jwtClaimsSet = mempty {iss = issuer, iat = currDate, exp = expDate}
      in encodeSigned (RSAPrivateKey iaAppPrivateKey) jwtClaimsSet

    -- | Make a request to GitHub to get an installation Auth token
    request :: FromJSON m => Url scheme -> Option scheme -> JSON -> IO m
    request url opts jwt = runReq def $ responseBody <$>
      req POST url NoReqBody
        jsonResponse -- specify how to interpret response
        (  header "Authorization" ("Bearer " <> encodeUtf8 jwt)
        <> header "Accept" "application/vnd.github.machine-man-preview+json"
        <> header "user-agent" "Haskell/github-app (Haskell/req)"
        <> opts
        )
