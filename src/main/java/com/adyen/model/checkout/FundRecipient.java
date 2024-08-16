/*
 * Adyen Checkout API
 *
 * The version of the OpenAPI document: 71
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.adyen.model.checkout;

import java.util.Objects;
import java.util.Arrays;
import java.util.Map;
import java.util.HashMap;
import com.adyen.model.checkout.Address;
import com.adyen.model.checkout.CardDetails;
import com.adyen.model.checkout.Name;
import com.adyen.model.checkout.SubMerchant;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.annotation.JsonValue;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.core.JsonProcessingException;


/**
 * FundRecipient
 */
@JsonPropertyOrder({
  FundRecipient.JSON_PROPERTY_I_B_A_N,
  FundRecipient.JSON_PROPERTY_BILLING_ADDRESS,
  FundRecipient.JSON_PROPERTY_PAYMENT_METHOD,
  FundRecipient.JSON_PROPERTY_SHOPPER_EMAIL,
  FundRecipient.JSON_PROPERTY_SHOPPER_NAME,
  FundRecipient.JSON_PROPERTY_SHOPPER_REFERENCE,
  FundRecipient.JSON_PROPERTY_STORED_PAYMENT_METHOD_ID,
  FundRecipient.JSON_PROPERTY_SUB_MERCHANT,
  FundRecipient.JSON_PROPERTY_TELEPHONE_NUMBER,
  FundRecipient.JSON_PROPERTY_WALLET_IDENTIFIER,
  FundRecipient.JSON_PROPERTY_WALLET_OWNER_TAX_ID
})

public class FundRecipient {
  public static final String JSON_PROPERTY_I_B_A_N = "IBAN";
  private String IBAN;

  public static final String JSON_PROPERTY_BILLING_ADDRESS = "billingAddress";
  private Address billingAddress;

  public static final String JSON_PROPERTY_PAYMENT_METHOD = "paymentMethod";
  private CardDetails paymentMethod;

  public static final String JSON_PROPERTY_SHOPPER_EMAIL = "shopperEmail";
  private String shopperEmail;

  public static final String JSON_PROPERTY_SHOPPER_NAME = "shopperName";
  private Name shopperName;

  public static final String JSON_PROPERTY_SHOPPER_REFERENCE = "shopperReference";
  private String shopperReference;

  public static final String JSON_PROPERTY_STORED_PAYMENT_METHOD_ID = "storedPaymentMethodId";
  private String storedPaymentMethodId;

  public static final String JSON_PROPERTY_SUB_MERCHANT = "subMerchant";
  private SubMerchant subMerchant;

  public static final String JSON_PROPERTY_TELEPHONE_NUMBER = "telephoneNumber";
  private String telephoneNumber;

  public static final String JSON_PROPERTY_WALLET_IDENTIFIER = "walletIdentifier";
  private String walletIdentifier;

  public static final String JSON_PROPERTY_WALLET_OWNER_TAX_ID = "walletOwnerTaxId";
  private String walletOwnerTaxId;

  public FundRecipient() { 
  }

  public FundRecipient IBAN(String IBAN) {
    this.IBAN = IBAN;
    return this;
  }

   /**
   * Fund Recipient Iban for C2C payments
   * @return IBAN
  **/
  @ApiModelProperty(value = "Fund Recipient Iban for C2C payments")
  @JsonProperty(JSON_PROPERTY_I_B_A_N)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getIBAN() {
    return IBAN;
  }


 /**
  * Fund Recipient Iban for C2C payments
  *
  * @param IBAN
  */ 
  @JsonProperty(JSON_PROPERTY_I_B_A_N)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setIBAN(String IBAN) {
    this.IBAN = IBAN;
  }


  public FundRecipient billingAddress(Address billingAddress) {
    this.billingAddress = billingAddress;
    return this;
  }

   /**
   * Get billingAddress
   * @return billingAddress
  **/
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_BILLING_ADDRESS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Address getBillingAddress() {
    return billingAddress;
  }


 /**
  * billingAddress
  *
  * @param billingAddress
  */ 
  @JsonProperty(JSON_PROPERTY_BILLING_ADDRESS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setBillingAddress(Address billingAddress) {
    this.billingAddress = billingAddress;
  }


  public FundRecipient paymentMethod(CardDetails paymentMethod) {
    this.paymentMethod = paymentMethod;
    return this;
  }

   /**
   * Get paymentMethod
   * @return paymentMethod
  **/
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_PAYMENT_METHOD)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public CardDetails getPaymentMethod() {
    return paymentMethod;
  }


 /**
  * paymentMethod
  *
  * @param paymentMethod
  */ 
  @JsonProperty(JSON_PROPERTY_PAYMENT_METHOD)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setPaymentMethod(CardDetails paymentMethod) {
    this.paymentMethod = paymentMethod;
  }


  public FundRecipient shopperEmail(String shopperEmail) {
    this.shopperEmail = shopperEmail;
    return this;
  }

   /**
   * The email address of the shopper.
   * @return shopperEmail
  **/
  @ApiModelProperty(value = "The email address of the shopper.")
  @JsonProperty(JSON_PROPERTY_SHOPPER_EMAIL)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getShopperEmail() {
    return shopperEmail;
  }


 /**
  * The email address of the shopper.
  *
  * @param shopperEmail
  */ 
  @JsonProperty(JSON_PROPERTY_SHOPPER_EMAIL)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setShopperEmail(String shopperEmail) {
    this.shopperEmail = shopperEmail;
  }


  public FundRecipient shopperName(Name shopperName) {
    this.shopperName = shopperName;
    return this;
  }

   /**
   * Get shopperName
   * @return shopperName
  **/
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_SHOPPER_NAME)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Name getShopperName() {
    return shopperName;
  }


 /**
  * shopperName
  *
  * @param shopperName
  */ 
  @JsonProperty(JSON_PROPERTY_SHOPPER_NAME)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setShopperName(Name shopperName) {
    this.shopperName = shopperName;
  }


  public FundRecipient shopperReference(String shopperReference) {
    this.shopperReference = shopperReference;
    return this;
  }

   /**
   * Required for recurring payments.  Your reference to uniquely identify this shopper, for example user ID or account ID. Minimum length: 3 characters. &gt; Your reference must not include personally identifiable information (PII), for example name or email address.
   * @return shopperReference
  **/
  @ApiModelProperty(value = "Required for recurring payments.  Your reference to uniquely identify this shopper, for example user ID or account ID. Minimum length: 3 characters. > Your reference must not include personally identifiable information (PII), for example name or email address.")
  @JsonProperty(JSON_PROPERTY_SHOPPER_REFERENCE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getShopperReference() {
    return shopperReference;
  }


 /**
  * Required for recurring payments.  Your reference to uniquely identify this shopper, for example user ID or account ID. Minimum length: 3 characters. &gt; Your reference must not include personally identifiable information (PII), for example name or email address.
  *
  * @param shopperReference
  */ 
  @JsonProperty(JSON_PROPERTY_SHOPPER_REFERENCE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setShopperReference(String shopperReference) {
    this.shopperReference = shopperReference;
  }


  public FundRecipient storedPaymentMethodId(String storedPaymentMethodId) {
    this.storedPaymentMethodId = storedPaymentMethodId;
    return this;
  }

   /**
   * This is the &#x60;recurringDetailReference&#x60; returned in the response when you created the token.
   * @return storedPaymentMethodId
  **/
  @ApiModelProperty(value = "This is the `recurringDetailReference` returned in the response when you created the token.")
  @JsonProperty(JSON_PROPERTY_STORED_PAYMENT_METHOD_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getStoredPaymentMethodId() {
    return storedPaymentMethodId;
  }


 /**
  * This is the &#x60;recurringDetailReference&#x60; returned in the response when you created the token.
  *
  * @param storedPaymentMethodId
  */ 
  @JsonProperty(JSON_PROPERTY_STORED_PAYMENT_METHOD_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setStoredPaymentMethodId(String storedPaymentMethodId) {
    this.storedPaymentMethodId = storedPaymentMethodId;
  }


  public FundRecipient subMerchant(SubMerchant subMerchant) {
    this.subMerchant = subMerchant;
    return this;
  }

   /**
   * Get subMerchant
   * @return subMerchant
  **/
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_SUB_MERCHANT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public SubMerchant getSubMerchant() {
    return subMerchant;
  }


 /**
  * subMerchant
  *
  * @param subMerchant
  */ 
  @JsonProperty(JSON_PROPERTY_SUB_MERCHANT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setSubMerchant(SubMerchant subMerchant) {
    this.subMerchant = subMerchant;
  }


  public FundRecipient telephoneNumber(String telephoneNumber) {
    this.telephoneNumber = telephoneNumber;
    return this;
  }

   /**
   * The telephone number of the shopper.
   * @return telephoneNumber
  **/
  @ApiModelProperty(value = "The telephone number of the shopper.")
  @JsonProperty(JSON_PROPERTY_TELEPHONE_NUMBER)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getTelephoneNumber() {
    return telephoneNumber;
  }


 /**
  * The telephone number of the shopper.
  *
  * @param telephoneNumber
  */ 
  @JsonProperty(JSON_PROPERTY_TELEPHONE_NUMBER)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setTelephoneNumber(String telephoneNumber) {
    this.telephoneNumber = telephoneNumber;
  }


  public FundRecipient walletIdentifier(String walletIdentifier) {
    this.walletIdentifier = walletIdentifier;
    return this;
  }

   /**
   * Indicates where the money is going.
   * @return walletIdentifier
  **/
  @ApiModelProperty(value = "Indicates where the money is going.")
  @JsonProperty(JSON_PROPERTY_WALLET_IDENTIFIER)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getWalletIdentifier() {
    return walletIdentifier;
  }


 /**
  * Indicates where the money is going.
  *
  * @param walletIdentifier
  */ 
  @JsonProperty(JSON_PROPERTY_WALLET_IDENTIFIER)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setWalletIdentifier(String walletIdentifier) {
    this.walletIdentifier = walletIdentifier;
  }


  public FundRecipient walletOwnerTaxId(String walletOwnerTaxId) {
    this.walletOwnerTaxId = walletOwnerTaxId;
    return this;
  }

   /**
   * Indicates the tax identifier of the fund recepient
   * @return walletOwnerTaxId
  **/
  @ApiModelProperty(value = "Indicates the tax identifier of the fund recepient")
  @JsonProperty(JSON_PROPERTY_WALLET_OWNER_TAX_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getWalletOwnerTaxId() {
    return walletOwnerTaxId;
  }


 /**
  * Indicates the tax identifier of the fund recepient
  *
  * @param walletOwnerTaxId
  */ 
  @JsonProperty(JSON_PROPERTY_WALLET_OWNER_TAX_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setWalletOwnerTaxId(String walletOwnerTaxId) {
    this.walletOwnerTaxId = walletOwnerTaxId;
  }


  /**
   * Return true if this FundRecipient object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    FundRecipient fundRecipient = (FundRecipient) o;
    return Objects.equals(this.IBAN, fundRecipient.IBAN) &&
        Objects.equals(this.billingAddress, fundRecipient.billingAddress) &&
        Objects.equals(this.paymentMethod, fundRecipient.paymentMethod) &&
        Objects.equals(this.shopperEmail, fundRecipient.shopperEmail) &&
        Objects.equals(this.shopperName, fundRecipient.shopperName) &&
        Objects.equals(this.shopperReference, fundRecipient.shopperReference) &&
        Objects.equals(this.storedPaymentMethodId, fundRecipient.storedPaymentMethodId) &&
        Objects.equals(this.subMerchant, fundRecipient.subMerchant) &&
        Objects.equals(this.telephoneNumber, fundRecipient.telephoneNumber) &&
        Objects.equals(this.walletIdentifier, fundRecipient.walletIdentifier) &&
        Objects.equals(this.walletOwnerTaxId, fundRecipient.walletOwnerTaxId);
  }

  @Override
  public int hashCode() {
    return Objects.hash(IBAN, billingAddress, paymentMethod, shopperEmail, shopperName, shopperReference, storedPaymentMethodId, subMerchant, telephoneNumber, walletIdentifier, walletOwnerTaxId);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class FundRecipient {\n");
    sb.append("    IBAN: ").append(toIndentedString(IBAN)).append("\n");
    sb.append("    billingAddress: ").append(toIndentedString(billingAddress)).append("\n");
    sb.append("    paymentMethod: ").append(toIndentedString(paymentMethod)).append("\n");
    sb.append("    shopperEmail: ").append(toIndentedString(shopperEmail)).append("\n");
    sb.append("    shopperName: ").append(toIndentedString(shopperName)).append("\n");
    sb.append("    shopperReference: ").append(toIndentedString(shopperReference)).append("\n");
    sb.append("    storedPaymentMethodId: ").append(toIndentedString(storedPaymentMethodId)).append("\n");
    sb.append("    subMerchant: ").append(toIndentedString(subMerchant)).append("\n");
    sb.append("    telephoneNumber: ").append(toIndentedString(telephoneNumber)).append("\n");
    sb.append("    walletIdentifier: ").append(toIndentedString(walletIdentifier)).append("\n");
    sb.append("    walletOwnerTaxId: ").append(toIndentedString(walletOwnerTaxId)).append("\n");
    sb.append("}");
    return sb.toString();
  }

  /**
   * Convert the given object to string with each line indented by 4 spaces
   * (except the first line).
   */
  private String toIndentedString(Object o) {
    if (o == null) {
      return "null";
    }
    return o.toString().replace("\n", "\n    ");
  }

/**
   * Create an instance of FundRecipient given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of FundRecipient
   * @throws JsonProcessingException if the JSON string is invalid with respect to FundRecipient
   */
  public static FundRecipient fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, FundRecipient.class);
  }
/**
  * Convert an instance of FundRecipient to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}

