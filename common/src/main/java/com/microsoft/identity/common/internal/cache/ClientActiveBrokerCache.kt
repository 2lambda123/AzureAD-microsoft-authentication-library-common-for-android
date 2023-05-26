package com.microsoft.identity.common.internal.cache

import com.microsoft.identity.common.java.interfaces.INameValueStorage
import com.microsoft.identity.common.java.interfaces.IStorageSupplier
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.time.Instant

class ClientActiveBrokerCache
internal constructor(private val storage: INameValueStorage<String>,
                     private val lock: Mutex): ActiveBrokerCache(storage, lock), IClientActiveBrokerCache {

    companion object {
        /**
         * File name of [ActiveBrokerCache] used by the SDK code.
         **/
        private const val BROKER_METADATA_CACHE_STORE_ON_SDK_SIDE_STORAGE_NAME = "BROKER_METADATA_CACHE_STORE_ON_SDK_SIDE"

        /**
         * The Mutex for all [ActiveBrokerCache] instances used by the SDK code.
         * (As of May 24, 2023... Kotlin has yet to officially support ReadWriteMutex.
         *  I don't think it's worth implementing our own (for now).
         *  If we eventually are seeing a perf hit, sure...)
         **/
        private val sSdkSideLock = Mutex()

        /**
         * If the caller is an SDK, invoke this function.
         *
         * @param storageSupplier an [IStorageSupplier] component.
         * @return a thread-safe [IActiveBrokerCache].
         */
        fun getBrokerMetadataStoreOnSdkSide(storageSupplier: IStorageSupplier)
                : IClientActiveBrokerCache {
            return ClientActiveBrokerCache(
                storage = storageSupplier.getEncryptedNameValueStore(
                    BROKER_METADATA_CACHE_STORE_ON_SDK_SIDE_STORAGE_NAME, String::class.java),
                lock = sSdkSideLock
            )
        }

        /**
         * Key for storing time which the client discovery should use AccountManager.
         **/
        const val SHOULD_USE_ACCOUNT_MANAGER_UNTIL_EPOCH_MILLISECONDS_KEY =
            "SHOULD_USE_ACCOUNT_MANAGER_UNTIL_EPOCH_MILLISECONDS_KEY"
    }

    override fun shouldUseAccountManager(): Boolean {
        return runBlocking {
            lock.withLock {
                storage.get(SHOULD_USE_ACCOUNT_MANAGER_UNTIL_EPOCH_MILLISECONDS_KEY)?.let { rawValue ->
                    rawValue.toLongOrNull()?.let { expiryDate ->
                        return@runBlocking Instant.now().toEpochMilli() < expiryDate
                    }
                }
                return@runBlocking false
            }
        }
    }

    override fun setShouldUseAccountManagerForTheNextMilliseconds(time: Long) {
        return runBlocking {
            lock.withLock {
                storage.put(SHOULD_USE_ACCOUNT_MANAGER_UNTIL_EPOCH_MILLISECONDS_KEY,
                    (Instant.now().toEpochMilli() + time).toString())
            }
        }
    }
}