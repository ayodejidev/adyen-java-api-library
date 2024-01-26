/*
 * Adyen Terminal API
 *
 * The version of the OpenAPI document: 1
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.adyen.model.terminal;

import java.util.Objects;
import java.util.Arrays;
import java.util.Map;
import java.util.HashMap;
import com.adyen.model.terminal.CardData;
import com.adyen.model.terminal.CheckData;
import com.adyen.model.terminal.MobileData;
import com.adyen.model.terminal.PaymentInstrumentType;
import com.adyen.model.terminal.StoredValueAccountID;
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
 * Sent in the result of the payment transaction. For a card, it could also be sent in the CardAcquisition response, to be processed by the Sale System. Data related to the instrument of payment for the transaction.
 */
@ApiModel(description = "Sent in the result of the payment transaction. For a card, it could also be sent in the CardAcquisition response, to be processed by the Sale System. Data related to the instrument of payment for the transaction.")
@JsonPropertyOrder({
  PaymentInstrumentData.JSON_PROPERTY_PAYMENT_INSTRUMENT_TYPE,
  PaymentInstrumentData.JSON_PROPERTY_PROTECTED_CARD_DATA,
  PaymentInstrumentData.JSON_PROPERTY_CARD_DATA,
  PaymentInstrumentData.JSON_PROPERTY_CHECK_DATA,
  PaymentInstrumentData.JSON_PROPERTY_MOBILE_DATA,
  PaymentInstrumentData.JSON_PROPERTY_STORED_VALUE_ACCOUNT_I_D
})

public class PaymentInstrumentData {
  public static final String JSON_PROPERTY_PAYMENT_INSTRUMENT_TYPE = "PaymentInstrumentType";
  private PaymentInstrumentType paymentInstrumentType;

  public static final String JSON_PROPERTY_PROTECTED_CARD_DATA = "ProtectedCardData";
  private String protectedCardData;

  public static final String JSON_PROPERTY_CARD_DATA = "CardData";
  private CardData cardData;

  public static final String JSON_PROPERTY_CHECK_DATA = "CheckData";
  private CheckData checkData;

  public static final String JSON_PROPERTY_MOBILE_DATA = "MobileData";
  private MobileData mobileData;

  public static final String JSON_PROPERTY_STORED_VALUE_ACCOUNT_I_D = "StoredValueAccountID";
  private StoredValueAccountID storedValueAccountID;

  public PaymentInstrumentData() { 
  }

  public PaymentInstrumentData paymentInstrumentType(PaymentInstrumentType paymentInstrumentType) {
    this.paymentInstrumentType = paymentInstrumentType;
    return this;
  }

   /**
   * Get paymentInstrumentType
   * @return paymentInstrumentType
  **/
  @ApiModelProperty(required = true, value = "")
  @JsonProperty(JSON_PROPERTY_PAYMENT_INSTRUMENT_TYPE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public PaymentInstrumentType getPaymentInstrumentType() {
    return paymentInstrumentType;
  }


 /**
  * paymentInstrumentType
  *
  * @param paymentInstrumentType
  */ 
  @JsonProperty(JSON_PROPERTY_PAYMENT_INSTRUMENT_TYPE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setPaymentInstrumentType(PaymentInstrumentType paymentInstrumentType) {
    this.paymentInstrumentType = paymentInstrumentType;
  }


  public PaymentInstrumentData protectedCardData(String protectedCardData) {
    this.protectedCardData = protectedCardData;
    return this;
  }

   /**
   * Get protectedCardData
   * @return protectedCardData
  **/
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_PROTECTED_CARD_DATA)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getProtectedCardData() {
    return protectedCardData;
  }


 /**
  * protectedCardData
  *
  * @param protectedCardData
  */ 
  @JsonProperty(JSON_PROPERTY_PROTECTED_CARD_DATA)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setProtectedCardData(String protectedCardData) {
    this.protectedCardData = protectedCardData;
  }


  public PaymentInstrumentData cardData(CardData cardData) {
    this.cardData = cardData;
    return this;
  }

   /**
   * Get cardData
   * @return cardData
  **/
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_CARD_DATA)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public CardData getCardData() {
    return cardData;
  }


 /**
  * cardData
  *
  * @param cardData
  */ 
  @JsonProperty(JSON_PROPERTY_CARD_DATA)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setCardData(CardData cardData) {
    this.cardData = cardData;
  }


  public PaymentInstrumentData checkData(CheckData checkData) {
    this.checkData = checkData;
    return this;
  }

   /**
   * Get checkData
   * @return checkData
  **/
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_CHECK_DATA)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public CheckData getCheckData() {
    return checkData;
  }


 /**
  * checkData
  *
  * @param checkData
  */ 
  @JsonProperty(JSON_PROPERTY_CHECK_DATA)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setCheckData(CheckData checkData) {
    this.checkData = checkData;
  }


  public PaymentInstrumentData mobileData(MobileData mobileData) {
    this.mobileData = mobileData;
    return this;
  }

   /**
   * Get mobileData
   * @return mobileData
  **/
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_MOBILE_DATA)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public MobileData getMobileData() {
    return mobileData;
  }


 /**
  * mobileData
  *
  * @param mobileData
  */ 
  @JsonProperty(JSON_PROPERTY_MOBILE_DATA)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setMobileData(MobileData mobileData) {
    this.mobileData = mobileData;
  }


  public PaymentInstrumentData storedValueAccountID(StoredValueAccountID storedValueAccountID) {
    this.storedValueAccountID = storedValueAccountID;
    return this;
  }

   /**
   * Get storedValueAccountID
   * @return storedValueAccountID
  **/
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_STORED_VALUE_ACCOUNT_I_D)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public StoredValueAccountID getStoredValueAccountID() {
    return storedValueAccountID;
  }


 /**
  * storedValueAccountID
  *
  * @param storedValueAccountID
  */ 
  @JsonProperty(JSON_PROPERTY_STORED_VALUE_ACCOUNT_I_D)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setStoredValueAccountID(StoredValueAccountID storedValueAccountID) {
    this.storedValueAccountID = storedValueAccountID;
  }


  /**
   * Return true if this PaymentInstrumentData object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    PaymentInstrumentData paymentInstrumentData = (PaymentInstrumentData) o;
    return Objects.equals(this.paymentInstrumentType, paymentInstrumentData.paymentInstrumentType) &&
        Objects.equals(this.protectedCardData, paymentInstrumentData.protectedCardData) &&
        Objects.equals(this.cardData, paymentInstrumentData.cardData) &&
        Objects.equals(this.checkData, paymentInstrumentData.checkData) &&
        Objects.equals(this.mobileData, paymentInstrumentData.mobileData) &&
        Objects.equals(this.storedValueAccountID, paymentInstrumentData.storedValueAccountID);
  }

  @Override
  public int hashCode() {
    return Objects.hash(paymentInstrumentType, protectedCardData, cardData, checkData, mobileData, storedValueAccountID);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class PaymentInstrumentData {\n");
    sb.append("    paymentInstrumentType: ").append(toIndentedString(paymentInstrumentType)).append("\n");
    sb.append("    protectedCardData: ").append(toIndentedString(protectedCardData)).append("\n");
    sb.append("    cardData: ").append(toIndentedString(cardData)).append("\n");
    sb.append("    checkData: ").append(toIndentedString(checkData)).append("\n");
    sb.append("    mobileData: ").append(toIndentedString(mobileData)).append("\n");
    sb.append("    storedValueAccountID: ").append(toIndentedString(storedValueAccountID)).append("\n");
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
   * Create an instance of PaymentInstrumentData given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of PaymentInstrumentData
   * @throws JsonProcessingException if the JSON string is invalid with respect to PaymentInstrumentData
   */
  public static PaymentInstrumentData fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, PaymentInstrumentData.class);
  }
/**
  * Convert an instance of PaymentInstrumentData to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}
