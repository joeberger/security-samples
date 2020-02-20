/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */

package com.example.android.biometricauth

import android.content.Intent
import android.content.SharedPreferences
import android.os.Bundle
import android.preference.PreferenceManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.KeyProperties.BLOCK_MODE_CBC
import android.security.keystore.KeyProperties.ENCRYPTION_PADDING_PKCS7
import android.security.keystore.KeyProperties.KEY_ALGORITHM_AES
import android.util.Base64
import android.util.Log
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import com.example.android.biometricauth.R.id.confirmation_message
import com.example.android.biometricauth.R.id.encrypted_message
import kotlinx.android.synthetic.main.activity_main.password_text
import java.io.IOException
import java.nio.charset.Charset
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.UnrecoverableKeyException
import java.security.cert.CertificateException
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.KeyGenerator
import javax.crypto.NoSuchPaddingException
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

/**
 * Main entry point for the sample, showing a backpack and "Purchase" button.
 */
class MainActivity : AppCompatActivity(),
        FingerprintAuthenticationDialogFragment.Callback {

    private lateinit var keyStore: KeyStore
    private lateinit var keyGenerator: KeyGenerator
    private lateinit var sharedPreferences: SharedPreferences
    private lateinit var biometricPrompt: BiometricPrompt
    private lateinit var ivParams: IvParameterSpec

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        setSupportActionBar(findViewById(R.id.toolbar))
        setupKeyStoreAndKeyGenerator()

        val encryptCipher: Cipher = setupCipher()
        sharedPreferences = PreferenceManager.getDefaultSharedPreferences(this)

        biometricPrompt = createBiometricPrompt()
        setUpButtons(encryptCipher)
    }

    /**
     * Enables or disables buttons and sets the appropriate click listeners.
     *
     * @param encryptCipher the default cipher, used for the encryption/decryption
     */
    private fun setUpButtons(encryptCipher: Cipher) {
        val loginButton = findViewById<Button>(R.id.login_button)
        val decryptButton =  findViewById<Button>(R.id.decrypt_button)

        if (BiometricManager.from(application).canAuthenticate() == BiometricManager.BIOMETRIC_SUCCESS) {
            // NOTE: this means the device supports biometric auth AND the user has setup the biometric auth on the phone.

            createKey(SYMMETRIC_KEY_NAME, false) // create private key to encrypt/decrypt password

            loginButton.run {
                isEnabled = true
                setOnClickListener(ButtonClickListener(encryptCipher, SYMMETRIC_KEY_NAME))
            }

            decryptButton.run {
                isEnabled = true
                setOnClickListener {
                    // clear out shared prefs
                    sharedPreferences.edit()
                        .remove(ENCRYPTED_PASSWORD_KEY)
                        .apply()

                    password_text.text.clear()
                }
            }
        } else {
            findViewById<TextView>(encrypted_message).run {
                visibility = View.VISIBLE
                text = getString(R.string.setup_lock_screen)
            }
            loginButton.isEnabled = false
            decryptButton.isEnabled = false
            // TODO: make this into a callback to let the caller know that biometrics is not supported
        }
    }

    /**
     * Sets up KeyStore and KeyGenerator
     */
    private fun setupKeyStoreAndKeyGenerator() {
        try {
            keyStore = KeyStore.getInstance(ANDROID_KEY_STORE)
        } catch (e: KeyStoreException) {
            throw RuntimeException("Failed to get an instance of KeyStore", e)
        }

        try {
            keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM_AES, ANDROID_KEY_STORE)
        } catch (e: Exception) {
            when (e) {
                is NoSuchAlgorithmException,
                is NoSuchProviderException ->
                    throw RuntimeException("Failed to get an instance of KeyGenerator", e)
                else -> throw e
            }
        }
    }

    /**
     * Sets up default cipher and a non-invalidated cipher
     */
    private fun setupCipher() : Cipher {
        val encryptCipher: Cipher
        try {
            val cipherString = "$KEY_ALGORITHM_AES/$BLOCK_MODE_CBC/$ENCRYPTION_PADDING_PKCS7"
            encryptCipher = Cipher.getInstance(cipherString)
        } catch (e: Exception) {
            when (e) {
                is NoSuchAlgorithmException,
                is NoSuchPaddingException ->
                    throw RuntimeException("Failed to get an instance of Cipher", e)
                else -> throw e
            }
        }
        return encryptCipher
    }


    /**
     * Initialize the [Cipher] instance with the created key in the [createKey] method.
     *
     * @param keyName the key name to init the cipher
     * @return `true` if initialization succeeded, `false` if the lock screen has been disabled or
     * reset after key generation, or if a fingerprint was enrolled after key generation.
     */
    private fun initCipher(cipher: Cipher, keyName: String, mode: Int): Boolean {
        Log.d(TAG, "********* Trying to init cipher with key: $keyName and mode: $mode")

        try {
            keyStore.load(null)

            val key = keyStore.getKey(keyName, null) as SecretKey

            if(mode == Cipher.ENCRYPT_MODE) {
                cipher.init(mode, key)
                ivParams = cipher.parameters.getParameterSpec(IvParameterSpec::class.java)
            } else {
                cipher.init(mode, key, ivParams)
            }
            return true
        } catch (e: Exception) {
            when (e) {
                is KeyPermanentlyInvalidatedException -> return false
                is KeyStoreException,
                is CertificateException,
                is UnrecoverableKeyException,
                is IOException,
                is NoSuchAlgorithmException,
                is InvalidKeyException -> throw RuntimeException("Failed to init Cipher", e)
                else -> throw e
            }
        }
    }


    /**
     * Proceed with the purchase operation
     *
     * @param withBiometrics `true` if the purchase was made by using a fingerprint
     * @param crypto the Crypto object
     */
    override fun onLogin(withBiometrics: Boolean, crypto: BiometricPrompt.CryptoObject?) {
        if (withBiometrics) {
            // If the user authenticated with fingerprint, verify using cryptography and then show
            // the confirmation message.
            // TODO: extract this into a function. It will need to check if password is in shared prefs AND the key and the IV exist
            if (sharedPreferences.getString(ENCRYPTED_PASSWORD_KEY, null) != null)
                crypto?.cipher?.let { tryDecrypt(it) }
            else
                crypto?.cipher?.let { tryEncrypt(it) }
        } else {
            // Authentication happened with backup password. Just show the confirmation message.
            showConfirmation()
        }
    }

    // Show confirmation message. Also show crypto information if fingerprint was used.
    private fun showConfirmation(encrypted: ByteArray? = null) {
        password_text.text.clear()

        findViewById<TextView>(confirmation_message).visibility = View.VISIBLE
        if (encrypted != null) {
            findViewById<TextView>(confirmation_message).run {
                text = context.getString(R.string.password_confirm_title)
            }
            findViewById<TextView>(encrypted_message).run {
                visibility = View.VISIBLE
                text = String(encrypted, Charset.defaultCharset())
            }
        }
    }

    /**
     * Tries to decrypt some data with the generated key from [createKey]. This only works if the
     * user just authenticated via fingerprint.
     */
    private fun tryDecrypt(cipher: Cipher) {
        Log.d(TAG, "********* Trying to decrypt")
        try {

            val encryptedPassword = Base64.decode(sharedPreferences.getString(ENCRYPTED_PASSWORD_KEY, null), Base64.DEFAULT)
            Log.d(TAG, "********* RAW encrypted password from shared prefs: "+sharedPreferences.getString(ENCRYPTED_PASSWORD_KEY, null))

            val decryptedPassword = cipher.doFinal(encryptedPassword)

            Log.d(TAG, "********* Decrypting Encrypted Password: "+String(encryptedPassword, Charset.defaultCharset()))

            Log.d(TAG, "********* decryptedPassword: "+String(decryptedPassword, Charset.defaultCharset()))

            // show me decrypted password
            showConfirmation(decryptedPassword)
        } catch (e: Exception) {
            when (e) {
                is BadPaddingException,
                is IllegalBlockSizeException -> {
                    Toast.makeText(this, "Failed to encrypt the data with the generated key. "
                            + "Retry the purchase", Toast.LENGTH_LONG).show()
                    Log.e(TAG, "Failed to encrypt the data with the generated key. ${e.message}")
                }
                else -> throw e
            }
        }
    }

    /**
     * Tries to encrypt some data with the generated key from [createKey]. This only works if the
     * user just authenticated via fingerprint.
     */
    private fun tryEncrypt(cipher: Cipher) {

        try {
            val plainTextPassword = password_text.text.toString()
            Log.d(TAG, "********* Trying to encrypt: $plainTextPassword")

            val encryptedPassword = cipher.doFinal(plainTextPassword.toByteArray())
            Log.d(TAG, "********* Successfully encrypted INTO: $encryptedPassword")
            
            // store encrypted password in shared prefs
            sharedPreferences.edit()
                .putString(ENCRYPTED_PASSWORD_KEY, Base64.encodeToString(encryptedPassword, Base64.DEFAULT))
                .apply()

            // show me the encrypted password:
            showConfirmation(encryptedPassword)
        } catch (e: Exception) {
            when (e) {
                is BadPaddingException,
                is IllegalBlockSizeException -> {
                    Toast.makeText(this, "Failed to encrypt the data with the generated key. "
                            + "Retry the LOGIN", Toast.LENGTH_LONG).show()
                    Log.e(TAG, "Failed to encrypt the data with the generated key. ${e.message}")
                }
                else -> throw e
            }
        }
    }

    /**
     * Creates a symmetric key in the Android Key Store which can only be used after the user has
     * authenticated with a fingerprint.
     *
     * @param keyName the name of the key to be created
     * @param invalidatedByBiometricEnrollment if `false` is passed, the created key will not be
     * invalidated even if a new fingerprint is enrolled. The default value is `true` - the key will
     * be invalidated if a new fingerprint is enrolled.
     */
    override fun createKey(keyName: String, invalidatedByBiometricEnrollment: Boolean) {
        // The enrolling flow for fingerprint. This is where you ask the user to set up fingerprint
        // for your flow. Use of keys is necessary if you need to know if the set of enrolled
        // fingerprints has changed.
        try {
            keyStore.load(null)

            val keyProperties = KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            val builder = KeyGenParameterSpec.Builder(keyName, keyProperties)
                    .setBlockModes(BLOCK_MODE_CBC)
                    .setUserAuthenticationRequired(true)
                    .setRandomizedEncryptionRequired(false) // this is only required for cyclical encryption, when each and every call requires a randomized private key.
                    .setEncryptionPaddings(ENCRYPTION_PADDING_PKCS7)
                    .setInvalidatedByBiometricEnrollment(invalidatedByBiometricEnrollment)

            keyGenerator.run {
                init(builder.build())
                generateKey()
            }
        } catch (e: Exception) {
            when (e) {
                is NoSuchAlgorithmException,
                is InvalidAlgorithmParameterException,
                is CertificateException,
                is IOException -> throw RuntimeException(e)
                else -> throw e
            }
        }
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.menu_main, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == R.id.action_settings) {
            val intent = Intent(this, SettingsActivity::class.java)
            startActivity(intent)
            return true
        }
        return super.onOptionsItemSelected(item)
    }

    private fun createBiometricPrompt(): BiometricPrompt {
        val executor = ContextCompat.getMainExecutor(this)

        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                Log.d(TAG, "$errorCode :: $errString")
                if (errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON) {
                    loginWithPassword() // Because negative button says use application password
                }
            }

            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
                Log.d(TAG, "Authentication failed for an unknown reason")
            }

            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                Log.d(TAG, "Authentication was successful")
                onLogin(true, result.cryptoObject)
            }
        }

        val biometricPrompt = BiometricPrompt(this, executor, callback)
        return biometricPrompt
    }

    private fun createPromptInfo(): BiometricPrompt.PromptInfo {
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle(getString(R.string.prompt_info_title))
                .setSubtitle(getString(R.string.prompt_info_subtitle))
                .setDescription(getString(R.string.prompt_info_description))
                .setConfirmationRequired(false)
                .setNegativeButtonText(getString(R.string.prompt_info_use_app_password))
                // .setDeviceCredentialAllowed(true) // Allow PIN/pattern/password authentication.
                // Also note that setDeviceCredentialAllowed and setNegativeButtonText are
                // incompatible so that if you uncomment one you must comment out the other
                .build()
        return promptInfo
    }

    private fun loginWithPassword() {
        Log.d(TAG, "Use app password")
        val fragment = FingerprintAuthenticationDialogFragment()
        fragment.setCallback(this@MainActivity)
        fragment.show(fragmentManager, DIALOG_FRAGMENT_TAG)
    }

    private inner class ButtonClickListener internal constructor(
            internal var cipher: Cipher,
            internal var keyName: String
    ) : View.OnClickListener {

        override fun onClick(view: View) {
            findViewById<View>(confirmation_message).visibility = View.GONE
            findViewById<View>(encrypted_message).visibility = View.GONE

            val promptInfo = createPromptInfo()

            val mode: Int = if (sharedPreferences.getString(ENCRYPTED_PASSWORD_KEY, null) != null)
                Cipher.DECRYPT_MODE
            else Cipher.ENCRYPT_MODE


            if (initCipher(cipher, keyName, mode)) {
                biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
            } else {
                loginWithPassword()
            }
        }
    }

    companion object {
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
        private const val DIALOG_FRAGMENT_TAG = "myFragment"
        private const val ENCRYPTED_PASSWORD_KEY = "ENCRYPTED_PASSWORD_KEY"
        private const val TAG = "MainActivity"
    }
}
