// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package com.microsoft.identity.common.internal.dto;

import com.google.gson.annotations.SerializedName;

/**
 * Accounts collect user displayable information about the user in each tenant (AAD) or environment
 * (MSA). Accounts also have fields necessary to lookup credentials.
 * <p>
 * Account schema only needs to be present, if there's a user available. For scenarios, where
 * there's no user present (e.g. client credential grant), only credential schema is necessary.
 */
public class Account extends AccountCredentialBase {

    ///////////////
    // Required fields
    ///////////////

    /**
     * Unique user identifier for a given authentication scheme.
     */
    @SerializedName("unique_id")
    private String mUniqueId;

    /**
     * Entity who issued the token represented as the host portion of a URL. For AAD it's host part
     * from the authority url with an optional port. For ADFS, it's the host part of the ADFS server
     * URL.
     */
    @SerializedName("environment")
    private String mEnvironment;

    /**
     * Full tenant or organizational identifier that account belongs to. Can be null.
     */
    @SerializedName("realm")
    private String mRealm;

    /**
     * Original authority specific account identifier. Can be needed for legacy purposes. OID for
     * AAD (in some unique cases subject instead of OID) and CID for MSA.
     */
    @SerializedName("authority_account_id")
    private String mAuthorityAccountId;

    /**
     * The primary username that represents the user (corresponds to the preferred_username claim
     * in the v2.0 endpoint). It could be an email address, phone number, or a generic username
     * without a specified format. Its value is mutable and might change over time. For MSA it's
     * email. For NTLM, NTLM username.
     */
    @SerializedName("username")
    private String mUsername;

    /**
     * Account’s authority type as string (ex: AAD, MSA, MSSTS, Other).
     * Set of account types is extensible.
     */
    @SerializedName("authority_type")
    private String mAuthorityType;

    ///////////////
    // Optional Fields
    ///////////////

    /**
     * Internal representation for guest users to the tenants. Corresponds to the “altsecid” claim
     * in the id_token for AAD.
     */
    @SerializedName("guest_id")
    private String mGuestId;

    /**
     * First name for this Account.
     */
    @SerializedName("first_name")
    private String mFirstName;

    /**
     * Last name for this Account.
     */
    @SerializedName("last_name")
    private String mLastName;

    /**
     * URL corresponding to a picture for this Account.
     */
    @SerializedName("avatar_url")
    private String mAvatarUrl;

    ///////////////
    // Accessor Methods
    ///////////////

    /**
     * Gets the unique_id.
     *
     * @return The unique_id to get.
     */
    public String getUniqueId() {
        return mUniqueId;
    }

    /**
     * Sets the unique_id.
     *
     * @param uniqueId The unique_id to get.
     */
    public void setUniqueId(final String uniqueId) {
        mUniqueId = uniqueId;
    }

    /**
     * Gets the environment.
     *
     * @return The environment to get.
     */
    public String getEnvironment() {
        return mEnvironment;
    }

    /**
     * Sets the environment.
     *
     * @param environment The environment to set.
     */
    public void setEnvironment(final String environment) {
        mEnvironment = environment;
    }

    /**
     * Gets the realm.
     *
     * @return The realm to get.
     */
    public String getRealm() {
        return mRealm;
    }

    /**
     * Sets the realm.
     *
     * @param realm The realm to set.
     */
    public void setRealm(final String realm) {
        mRealm = realm;
    }

    /**
     * Gets the authority_account_id.
     *
     * @return The authority_account_id to get.
     */
    public String getAuthorityAccountId() {
        return mAuthorityAccountId;
    }

    /**
     * Sets the authority_account_id.
     *
     * @param authorityAccountId The authority_account_id to set.
     */
    public void setAuthorityAccountId(final String authorityAccountId) {
        mAuthorityAccountId = authorityAccountId;
    }

    /**
     * Gets the username.
     *
     * @return The username to get.
     */
    public String getUsername() {
        return mUsername;
    }

    /**
     * Sets the username.
     *
     * @param username The username to set.
     */
    public void setUsername(final String username) {
        mUsername = username;
    }

    /**
     * Gets the authority_type.
     *
     * @return The authority_type to get.
     */
    public String getAuthorityType() {
        return mAuthorityType;
    }

    /**
     * Sets the authority_type.
     *
     * @param authorityType The authority_type to set.
     */
    public void setAuthorityType(final String authorityType) {
        mAuthorityType = authorityType;
    }

    /**
     * Gets the guest_id.
     *
     * @return The guest_id to get.
     */
    public String getGuestId() {
        return mGuestId;
    }

    /**
     * Sets the guest_id.
     *
     * @param guestId The guest_id to set.
     */
    public void setGuestId(final String guestId) {
        mGuestId = guestId;
    }

    /**
     * Gets the first_name;
     *
     * @return The first_name to get.
     */
    public String getFirstName() {
        return mFirstName;
    }

    /**
     * Sets the first_name;
     *
     * @param firstName The first_name to set.
     */
    public void setFirstName(final String firstName) {
        mFirstName = firstName;
    }

    /**
     * Gets the last_name.
     *
     * @return The last_name to get.
     */
    public String getLastName() {
        return mLastName;
    }

    /**
     * Sets the last_name.
     *
     * @param lastName The last_name to set.
     */
    public void setLastName(final String lastName) {
        mLastName = lastName;
    }

    /**
     * Gets the avatar_url.
     *
     * @return The avatar_url to get.
     */
    public String getAvatarUrl() {
        return mAvatarUrl;
    }

    /**
     * Sets the avatar_url.
     *
     * @param avatarUrl The avatar_url to set.
     */
    public void setAvatarUrl(final String avatarUrl) {
        mAvatarUrl = avatarUrl;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Account account = (Account) o;

        if (mUniqueId != null ? !mUniqueId.equals(account.mUniqueId) : account.mUniqueId != null)
            return false;
        if (mEnvironment != null ? !mEnvironment.equals(account.mEnvironment) : account.mEnvironment != null)
            return false;
        if (mRealm != null ? !mRealm.equals(account.mRealm) : account.mRealm != null) return false;
        if (mAuthorityAccountId != null ? !mAuthorityAccountId.equals(account.mAuthorityAccountId) : account.mAuthorityAccountId != null)
            return false;
        if (mUsername != null ? !mUsername.equals(account.mUsername) : account.mUsername != null)
            return false;
        if (mAuthorityType != null ? !mAuthorityType.equals(account.mAuthorityType) : account.mAuthorityType != null)
            return false;
        if (mGuestId != null ? !mGuestId.equals(account.mGuestId) : account.mGuestId != null)
            return false;
        if (mFirstName != null ? !mFirstName.equals(account.mFirstName) : account.mFirstName != null)
            return false;
        if (mLastName != null ? !mLastName.equals(account.mLastName) : account.mLastName != null)
            return false;
        return mAvatarUrl != null ? mAvatarUrl.equals(account.mAvatarUrl) : account.mAvatarUrl == null;
    }

    @Override
    public int hashCode() {
        int result = mUniqueId != null ? mUniqueId.hashCode() : 0;
        result = 31 * result + (mEnvironment != null ? mEnvironment.hashCode() : 0);
        result = 31 * result + (mRealm != null ? mRealm.hashCode() : 0);
        result = 31 * result + (mAuthorityAccountId != null ? mAuthorityAccountId.hashCode() : 0);
        result = 31 * result + (mUsername != null ? mUsername.hashCode() : 0);
        result = 31 * result + (mAuthorityType != null ? mAuthorityType.hashCode() : 0);
        result = 31 * result + (mGuestId != null ? mGuestId.hashCode() : 0);
        result = 31 * result + (mFirstName != null ? mFirstName.hashCode() : 0);
        result = 31 * result + (mLastName != null ? mLastName.hashCode() : 0);
        result = 31 * result + (mAvatarUrl != null ? mAvatarUrl.hashCode() : 0);
        return result;
    }
}
