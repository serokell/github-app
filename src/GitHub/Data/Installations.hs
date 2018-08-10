{- This Source Code Form is subject to the terms of the Mozilla Public
 - License, v. 2.0. If a copy of the MPL was not distributed with this
 - file, You can obtain one at http://mozilla.org/MPL/2.0/.
 -}

{-# LANGUAGE CPP #-}

module GitHub.Data.Installations where

import GitHub.Data.Apps (App)
import GitHub.Data.Id (Id)
import GitHub.Data.URL (URL)
import GitHub.Internal.Prelude
import Prelude ()


data Installation = Installation
    { installationId               :: !(Id Installation)
--    , installationAccount
    , installationAccesssTokensUrl :: !URL
    , installationRepositoriesUrl  :: !URL
    , installationHtmlUrl          :: !URL
    , installationAppId            :: (Id App)
--    , installationTargetId
--    , installationTargetType
--    , installationPermissions
--    , installationEvents
--    , installationSingleFileName
--    , installationRepositorySelection
    }
    deriving (Show, Data, Typeable, Eq, Ord, Generic)

instance NFData Installation where rnf = genericRnf
instance Binary Installation
