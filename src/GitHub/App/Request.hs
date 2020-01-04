{- This Source Code Form is subject to the terms of the Mozilla Public
 - License, v. 2.0. If a copy of the MPL was not distributed with this
 - file, You can obtain one at http://mozilla.org/MPL/2.0/.
 -}

{-# LANGUAGE CPP #-}

module GitHub.App.Request
       ( executeAppRequest
       , executeAppRequestWithMgr
       ) where

import Data.Aeson (FromJSON)
import GitHub.Data (Error (..))
import GitHub.Data.Request (Request)
import GitHub.Request (executeRequestWithMgr)
import Network.HTTP.Client (Manager)
import Network.HTTP.Client.TLS (newTlsManager)

import GitHub.App.Auth (InstallationAuth, obtainAccessToken)


executeAppRequest :: FromJSON a => InstallationAuth -> Request k a -> IO (Either Error a)
executeAppRequest instAuth req = do
    manager <- newTlsManager
    x <- executeAppRequestWithMgr manager instAuth req
#if !MIN_VERSION_http_client(0, 4, 18)
    closeManager manager
#endif
    pure x

executeAppRequestWithMgr
    :: FromJSON a
    => Manager
    -> InstallationAuth
    -> Request k a
    -> IO (Either Error a)
executeAppRequestWithMgr mgr instAuth req = obtainAccessToken mgr instAuth >>= \case
    Right auth -> executeRequestWithMgr mgr auth req
    Left  err  -> pure $ Left err
