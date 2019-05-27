{- This Source Code Form is subject to the terms of the Mozilla Public
 - License, v. 2.0. If a copy of the MPL was not distributed with this
 - file, You can obtain one at http://mozilla.org/MPL/2.0/.
 -}

module Crypto.PubKey.RSA.Read
       ( ReadRsaKeyError (..)
       , readRsaPem
       ) where

import Crypto.PubKey.RSA (PrivateKey)
import Data.X509 (PrivKey (PrivKeyRSA))
import Data.ByteString (ByteString)
import Data.X509.Memory (readKeyFileFromMemory)


data ReadRsaKeyError
    = SingleKeyExpected { rrkeActualKeysCount :: Int }
    | NotRsaKey

readRsaPem :: ByteString -> Either ReadRsaKeyError PrivateKey
readRsaPem bs =
    case readKeyFileFromMemory bs of
        [k] -> case k of
            PrivKeyRSA rsaKey -> Right rsaKey
            _                 -> Left NotRsaKey
        l   -> Left $ SingleKeyExpected (length l)
