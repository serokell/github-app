{-# LANGUAGE TemplateHaskell #-}

module GitHub.App
  (
   , InstallationAuth 
   , authenticateInstallation
   , createInstToken
  ) where

import Universum hiding          (exp, Option)
import Crypto.Types.PubKey.RSA   (PrivateKey(..))
import Data.Aeson                (FromJSON (..), withObject, (.:))
import Data.Default.Class        (def)
import GitHub.Auth               (Auth (..))
import Lens.Micro.Platform       (makeLenses, (^.))
import Network.HTTP.Req          (POST (..), NoReqBody (..), Option, Url, header, https,
                                   jsonResponse, req, responseBody, runReq, (/:))
import Data.Time.Clock           (UTCTime (..))
import Data.Time.Clock.POSIX     (POSIXTime,getPOSIXTime, utcTimeToPOSIXSeconds)
import Web.JWT                   (Signer(..), JSON, JWTClaimsSet(..), encodeSigned, numericDate, stringOrURI)
import qualified Prelude as Show (Show, show)
import qualified  Data.Text as T (takeWhileEnd, takeWhile)

-- | Json Web Token expiration time. Maximun accepted by github is 10 minutes. 
jwtExpTime :: POSIXTime
jwtExpTime = 600.0 

-- | Installation key expiration time. It is fixed by github and is equal to 1 hour. 
instKeyExpTime :: POSIXTime
instKeyExpTime = 3600.0

-- | Time preserved to be on the safe side. 
-- if expiration time of installation auth token <= current time + bufferTime 
-- then installation Auth token shoul be updated. 
bufferTime :: POSIXTime 
bufferTime = instKeyExpTime * 0.25

-- | base URL of api
baseURL :: Text
baseURL = "api.github.com"

type BaseURL = Text 
type InstallationId = Text 


-- | Github installation Auth token 
data GTAToken = GTAToken 
    {
        instToken  :: !Text,      -- ^ Installation token 
        expireAt   :: !POSIXTime  -- ^ expiration time 
    }

-- | Main installation auth info for application. 
-- it containes immutable app information and app installation token
-- which shoud be updated at least once per hour  
data InstallationAuth = InstallationAuth 
    {
        _appId          :: !Int,           -- ^ application id 
        _appPrivateKey  :: !PrivateKey,    -- ^ Private key to sign token requests  
        _installationId :: !Text,          -- ^ Installation id 
        _token          :: IORef GTAToken  -- ^ Installation Auth token. 
    } 

makeLenses '' InstallationAuth

instance FromJSON GTAToken where
    parseJSON = withObject "Github installation token" $ \o -> do 
        instToken   <- o .: "token"  
        expireAtM   <- expPOSIXtime <$> o .: "expires_at"
        case expireAtM of 
            Nothing       -> fail "Failed to parse expiraion time."
            Just expireAt -> return GTAToken{..}

-- | newtype for failed JSON Web token generation.
newtype FailedGenerateJWT = FailedGenerateJWT Text

instance Show.Show FailedGenerateJWT where
    show (FailedGenerateJWT err) = toString err

instance Exception FailedGenerateJWT

-- | Checks if current app installation token is not expired. If it is not, than it just returns token 
-- with OAuth wrapping. 
-- Otherwise it call function that gets new token from github and writes it to IORef, and also returns that new token. 
authenticateInstallation :: InstallationAuth -> IO Auth
authenticateInstallation instAuth = do 
    gtaToken    <- readIORef (instAuth ^. token)
    currentTime <- getPOSIXTime
    if (expireAt gtaToken) - currentTime >= bufferTime 
    then return $ OAuth $ encodeUtf8 $ instToken gtaToken
    else do 
        let applicationId = instAuth ^. appId
        OAuth <$> encodeUtf8 <$> instToken <$> (join $ readIORef <$> renewInstAuthToken instAuth) 


-- | Gets new token from github and writes it to IORef in given InstallationAuth. Also returns that token. 
renewInstAuthToken :: InstallationAuth -> IO (IORef GTAToken) 
renewInstAuthToken instAuth = do 
    time    <- getPOSIXTime
    let tkn = instAuth ^. token
    case (makeJWT time (instAuth ^. appId) (instAuth ^. appPrivateKey)) of 
        Left  err  -> throwM (FailedGenerateJWT err) 
        Right jwt  -> do 
            t <- request (https baseURL /: "installations" /: (instAuth ^. installationId) /: "access_tokens") mempty jwt    
            writeIORef tkn t 
            return tkn

-- | Creates new InstallationAuth value. Useing this function is the only way to create InstallationAuth value, 
-- because we don't export constructors. 
createInstAuth :: Int -> PrivateKey -> InstallationId -> IO InstallationAuth 
createInstAuth appId key instId = do 
    time    <- getPOSIXTime
    case (makeJWT time appId key) of 
        Left  err  -> throwM (FailedGenerateJWT err) 
        Right jwt  -> do 
            t      <- request (https baseURL /: "installations" /: instId /: "access_tokens") mempty jwt
            token  <- newIORef t
            return $ InstallationAuth appId key instId token
    

-- | Creates JSON Web Token for given application Id using application's privateKey. 
makeJWT :: POSIXTime -> Int -> PrivateKey -> Either Text JSON 
makeJWT currentTime appId appPrivateKey = do 
    let currDate = numericDate currentTime 
    let expDate  = numericDate (currentTime + jwtExpTime)
    if (currDate >> expDate) == Nothing 
    then Left "Failed to convert time to numericDate."
    else do
        let issuer = stringOrURI $ show appId 
        if issuer == Nothing 
        then Left $ "Failed to convert id " <> show appId <> " to StringOrURI type"
        else do 
            let jwtClaimsSet = mempty {iss = issuer, iat = currDate, exp = expDate}
            return $ encodeSigned (RSAPrivateKey appPrivateKey) jwtClaimsSet

-- | Make request to github to get installation Auth token. 
request :: FromJSON m => Url scheme -> Option scheme -> JSON -> IO m
request url opts jwt = runReq def $ responseBody <$>
  req POST url NoReqBody
    jsonResponse -- specify how to interpret response
     (  header "Authorization" ("Bearer " <> encodeUtf8 jwt)
     <> header "Accept" "application/vnd.github.machine-man-preview+json"
     <> header "user-agent" "req"
     <> opts
     )

-- | It reads expiration time of token from github's format to POSIXTime.
expPOSIXtime :: Text -> Maybe POSIXTime
expPOSIXtime txt = 
  let date = T.takeWhile (/='T') txt 
      time = T.takeWhile (/='Z') $ T.takeWhileEnd (/='T') txt 
  in  (utcTimeToPOSIXSeconds . fst) <$> (safeHead $ reads $ toString $ date <> " " <> time <> ".0 UTC")