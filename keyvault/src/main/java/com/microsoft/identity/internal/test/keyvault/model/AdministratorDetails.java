/*
 * KeyVaultClient
 * The key vault client performs cryptographic key operations and vault operations against the Key Vault service.
 *
 * OpenAPI spec version: 2016-10-01
 * 
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */


package com.microsoft.identity.internal.test.keyvault.model;

import java.util.Objects;

import com.google.gson.annotations.SerializedName;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;

/**
 * Details of the organization administrator of the certificate issuer.
 */
@ApiModel(description = "Details of the organization administrator of the certificate issuer.")

public class AdministratorDetails {
  @SerializedName("first_name")
  private String firstName = null;

  @SerializedName("last_name")
  private String lastName = null;

  @SerializedName("email")
  private String email = null;

  @SerializedName("phone")
  private String phone = null;

  public AdministratorDetails firstName(String firstName) {
    this.firstName = firstName;
    return this;
  }

   /**
   * First name.
   * @return firstName
  **/
  @ApiModelProperty(value = "First name.")
  public String getFirstName() {
    return firstName;
  }

  public void setFirstName(String firstName) {
    this.firstName = firstName;
  }

  public AdministratorDetails lastName(String lastName) {
    this.lastName = lastName;
    return this;
  }

   /**
   * Last name.
   * @return lastName
  **/
  @ApiModelProperty(value = "Last name.")
  public String getLastName() {
    return lastName;
  }

  public void setLastName(String lastName) {
    this.lastName = lastName;
  }

  public AdministratorDetails email(String email) {
    this.email = email;
    return this;
  }

   /**
   * Email addresss.
   * @return email
  **/
  @ApiModelProperty(value = "Email addresss.")
  public String getEmail() {
    return email;
  }

  public void setEmail(String email) {
    this.email = email;
  }

  public AdministratorDetails phone(String phone) {
    this.phone = phone;
    return this;
  }

   /**
   * Phone number.
   * @return phone
  **/
  @ApiModelProperty(value = "Phone number.")
  public String getPhone() {
    return phone;
  }

  public void setPhone(String phone) {
    this.phone = phone;
  }


  @Override
  public boolean equals(java.lang.Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    AdministratorDetails administratorDetails = (AdministratorDetails) o;
    return Objects.equals(this.firstName, administratorDetails.firstName) &&
        Objects.equals(this.lastName, administratorDetails.lastName) &&
        Objects.equals(this.email, administratorDetails.email) &&
        Objects.equals(this.phone, administratorDetails.phone);
  }

  @Override
  public int hashCode() {
    return Objects.hash(firstName, lastName, email, phone);
  }


  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class AdministratorDetails {\n");
    
    sb.append("    firstName: ").append(toIndentedString(firstName)).append("\n");
    sb.append("    lastName: ").append(toIndentedString(lastName)).append("\n");
    sb.append("    email: ").append(toIndentedString(email)).append("\n");
    sb.append("    phone: ").append(toIndentedString(phone)).append("\n");
    sb.append("}");
    return sb.toString();
  }

  /**
   * Convert the given object to string with each line indented by 4 spaces
   * (except the first line).
   */
  private String toIndentedString(java.lang.Object o) {
    if (o == null) {
      return "null";
    }
    return o.toString().replace("\n", "\n    ");
  }

}

