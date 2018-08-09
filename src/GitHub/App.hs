{- This Source Code Form is subject to the terms of the Mozilla Public
 - License, v. 2.0. If a copy of the MPL was not distributed with this
 - file, You can obtain one at http://mozilla.org/MPL/2.0/.
 -}

{-# LANGUAGE TemplateHaskell #-}

module GitHub.App
       ( InstallationAuth
       , authenticateInstallation
       , createInstAuth
       ) where

import Universum hiding (Option, exp)

import Crypto.Types.PubKey.RSA (PrivateKey (..))
import Data.Aeson (FromJSON (..), withObject, (.:))
import Data.Default.Class (def)
import Data.Time (NominalDiffTime (..), UTCTime (..), addUTCTime, defaultTimeLocale, diffUTCTime,
                  getCurrentTime, iso8601DateFormat, parseTimeM)
import Data.Time.Clock.POSIX (utcTimeToPOSIXSeconds)
import GitHub.Auth (Auth (..))
import Lens.Micro.Platform (makeLenses, (^.))
import Network.HTTP.Req (NoReqBody (..), Option, POST (..), Url, header, https, jsonResponse, req,
                         responseBody, runReq, (/:))
import Web.JWT (JSON, JWTClaimsSet (..), Signer (..), encodeSigned, numericDate, stringOrURI)


-- | Json Web Token expiration time. Maximun accepted by github is 10 minutes.
jwtExpTime :: NominalDiffTime
jwtExpTime = 600.0

-- | Installation key expiration time. It is fixed by github and is equal to 1 hour.
instKeyExpTime :: NominalDiffTime
instKeyExpTime = 3600.0

-- | Time preserved to be on the safe side.
-- if expiration time of installation auth token <= current time + bufferTime
-- then installation Auth token shoul be updated.
bufferTime :: NominalDiffTime
bufferTime = instKeyExpTime * 0.25

-- | base URL of api
baseURL :: Text
baseURL = "api.github.com"

type BaseURL = Text
type InstallationId = Text


-- | Github installation access token
data InstallationToken = InstallationToken
    { getToken          :: ByteString
    , getExpirationTime :: UTCTime
    } deriving (Show)

instance FromJSON InstallationToken where
    parseJSON = withObject "installation token" $ \o -> InstallationToken
        <$> ((encodeUtf8 :: Text -> ByteString) <$> o .: "token")
        <*> (either fail pure =<< parseExpiresAt <$> o .: "expires_at")
      where
        parseExpiresAt :: String -> Either String UTCTime
        parseExpiresAt = parseTimeM True defaultTimeLocale (iso8601DateFormat (Just "%H:%M:%SZ"))

-- | Main installation auth info for application.
-- it containes immutable app information and app installation token
-- which shoud be updated at least once per hour
data InstallationAuth = InstallationAuth
    {  _appId          :: !Int                -- ^ application id
    ,  _appPrivateKey  :: !PrivateKey         -- ^ Private key to sign token requests
    ,  _installationId :: !Text               -- ^ Installation id
    ,  _token          :: !(MVar InstallationToken)  -- ^ Installation Auth token.
    }

makeLenses '' InstallationAuth

-- | Checks if current app installation token is not expired. If it is not, than it just returns token
-- with OAuth wrapping.
-- Otherwise it call function that gets new token from github and writes it to IORef,
-- and also returns that new token.
authenticateInstallation :: InstallationAuth -> IO Auth
authenticateInstallation instAuth = do
    gtaToken    <- readMVar (instAuth ^. token)
    currentTime <- getCurrentTime
    if getExpirationTime gtaToken `diffUTCTime` currentTime >= bufferTime
    then return $ OAuth $ getToken gtaToken
    else do
        updatedToken   <- takeMVar (instAuth ^. token)
        renewInstAuthToken instAuth
        updatedToken   <- readMVar (instAuth ^. token)
        return $ OAuth $ getToken updatedToken

-- | Creates new InstallationAuth value. Useing this function is the only way to create
-- InstallationAuth value, because we don't export constructors.
createInstAuth :: Int -> PrivateKey -> InstallationId -> IO InstallationAuth
createInstAuth appId key instId = do
    token  <- newEmptyMVar
    let instAuth = InstallationAuth appId key instId token
    _      <- renewInstAuthToken instAuth
    return instAuth

-- | Gets new token from github and writes it to IORef in given InstallationAuth.
renewInstAuthToken :: InstallationAuth -> IO ()
renewInstAuthToken instAuth = do
    time    <- getCurrentTime
    let tkn = instAuth ^. token
    let jwt = makeJWT time (instAuth ^. appId) (instAuth ^. appPrivateKey)
    t <- request (https baseURL /: "installations" /: (instAuth ^. installationId) /: "access_tokens") mempty jwt
    putMVar tkn t
    return ()

-- | Creates JSON Web Token for given application Id using application's privateKey.
makeJWT :: UTCTime -> Int -> PrivateKey -> JSON
makeJWT currentTime appId appPrivateKey =
  let currDate     = numericDate $ utcTimeToPOSIXSeconds currentTime
      expDate      = numericDate $ utcTimeToPOSIXSeconds $ jwtExpTime `addUTCTime` currentTime
      issuer       = stringOrURI $ show appId
      jwtClaimsSet = mempty {iss = issuer, iat = currDate, exp = expDate}
  in encodeSigned (RSAPrivateKey appPrivateKey) jwtClaimsSet

-- | Make request to github to get installation Auth token.
request :: FromJSON m => Url scheme -> Option scheme -> JSON -> IO m
request url opts jwt = runReq def $ responseBody <$>
  req POST url NoReqBody
    jsonResponse -- specify how to interpret response
     (  header "Authorization" ("Bearer " <> encodeUtf8 jwt)
     <> header "Accept" "application/vnd.github.machine-man-preview+json"
     <> header "user-agent" "Haskell req-1.2.1"
     <> opts
     )
