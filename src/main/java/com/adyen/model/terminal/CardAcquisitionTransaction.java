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
import com.adyen.model.terminal.LoyaltyHandling;
import com.adyen.model.terminal.PaymentType;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.annotation.JsonValue;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.core.JsonProcessingException;


/**
 * CardAcquisitionTransaction
 */
@JsonPropertyOrder({
  CardAcquisitionTransaction.JSON_PROPERTY_ALLOWED_PAYMENT_BRAND,
  CardAcquisitionTransaction.JSON_PROPERTY_ALLOWED_LOYALTY_BRAND,
  CardAcquisitionTransaction.JSON_PROPERTY_LOYALTY_HANDLING,
  CardAcquisitionTransaction.JSON_PROPERTY_CUSTOMER_LANGUAGE,
  CardAcquisitionTransaction.JSON_PROPERTY_FORCE_ENTRY_MODE,
  CardAcquisitionTransaction.JSON_PROPERTY_FORCE_CUSTOMER_SELECTION_FLAG,
  CardAcquisitionTransaction.JSON_PROPERTY_TOTAL_AMOUNT,
  CardAcquisitionTransaction.JSON_PROPERTY_PAYMENT_TYPE,
  CardAcquisitionTransaction.JSON_PROPERTY_CASH_BACK_FLAG
})

public class CardAcquisitionTransaction {
  public static final String JSON_PROPERTY_ALLOWED_PAYMENT_BRAND = "AllowedPaymentBrand";
  private List<String> allowedPaymentBrand = null;

  public static final String JSON_PROPERTY_ALLOWED_LOYALTY_BRAND = "AllowedLoyaltyBrand";
  private List<String> allowedLoyaltyBrand = null;

  public static final String JSON_PROPERTY_LOYALTY_HANDLING = "LoyaltyHandling";
  private LoyaltyHandling loyaltyHandling;

  public static final String JSON_PROPERTY_CUSTOMER_LANGUAGE = "CustomerLanguage";
  private String customerLanguage;

  /**
   * Gets or Sets forceEntryMode
   */
  public enum ForceEntryModeEnum {
    CHECKREADER("CheckReader"),
    
    CONTACTLESS("Contactless"),
    
    FILE("File"),
    
    ICC("ICC"),
    
    KEYED("Keyed"),
    
    MAGSTRIPE("MagStripe"),
    
    MANUAL("Manual"),
    
    RFID("RFID"),
    
    SCANNED("Scanned"),
    
    SYNCHRONOUSICC("SynchronousICC"),
    
    TAPPED("Tapped");

    private String value;

    ForceEntryModeEnum(String value) {
      this.value = value;
    }

    @JsonValue
    public String getValue() {
      return value;
    }

    @Override
    public String toString() {
      return String.valueOf(value);
    }

    @JsonCreator
    public static ForceEntryModeEnum fromValue(String value) {
      for (ForceEntryModeEnum b : ForceEntryModeEnum.values()) {
        if (b.value.equals(value)) {
          return b;
        }
      }
      throw new IllegalArgumentException("Unexpected value '" + value + "'");
    }
  }

  public static final String JSON_PROPERTY_FORCE_ENTRY_MODE = "ForceEntryMode";
  private List<ForceEntryModeEnum> forceEntryMode = null;

  public static final String JSON_PROPERTY_FORCE_CUSTOMER_SELECTION_FLAG = "ForceCustomerSelectionFlag";
  private Boolean forceCustomerSelectionFlag;

  public static final String JSON_PROPERTY_TOTAL_AMOUNT = "TotalAmount";
  private BigDecimal totalAmount;

  public static final String JSON_PROPERTY_PAYMENT_TYPE = "PaymentType";
  private PaymentType paymentType;

  public static final String JSON_PROPERTY_CASH_BACK_FLAG = "CashBackFlag";
  private Boolean cashBackFlag;

  public CardAcquisitionTransaction() { 
  }

  public CardAcquisitionTransaction allowedPaymentBrand(List<String> allowedPaymentBrand) {
    this.allowedPaymentBrand = allowedPaymentBrand;
    return this;
  }

  public CardAcquisitionTransaction addAllowedPaymentBrandItem(String allowedPaymentBrandItem) {
    if (this.allowedPaymentBrand == null) {
      this.allowedPaymentBrand = new ArrayList<>();
    }
    this.allowedPaymentBrand.add(allowedPaymentBrandItem);
    return this;
  }

   /**
   * Get allowedPaymentBrand
   * @return allowedPaymentBrand
  **/
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_ALLOWED_PAYMENT_BRAND)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public List<String> getAllowedPaymentBrand() {
    return allowedPaymentBrand;
  }


 /**
  * allowedPaymentBrand
  *
  * @param allowedPaymentBrand
  */ 
  @JsonProperty(JSON_PROPERTY_ALLOWED_PAYMENT_BRAND)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setAllowedPaymentBrand(List<String> allowedPaymentBrand) {
    this.allowedPaymentBrand = allowedPaymentBrand;
  }


  public CardAcquisitionTransaction allowedLoyaltyBrand(List<String> allowedLoyaltyBrand) {
    this.allowedLoyaltyBrand = allowedLoyaltyBrand;
    return this;
  }

  public CardAcquisitionTransaction addAllowedLoyaltyBrandItem(String allowedLoyaltyBrandItem) {
    if (this.allowedLoyaltyBrand == null) {
      this.allowedLoyaltyBrand = new ArrayList<>();
    }
    this.allowedLoyaltyBrand.add(allowedLoyaltyBrandItem);
    return this;
  }

   /**
   * Get allowedLoyaltyBrand
   * @return allowedLoyaltyBrand
  **/
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_ALLOWED_LOYALTY_BRAND)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public List<String> getAllowedLoyaltyBrand() {
    return allowedLoyaltyBrand;
  }


 /**
  * allowedLoyaltyBrand
  *
  * @param allowedLoyaltyBrand
  */ 
  @JsonProperty(JSON_PROPERTY_ALLOWED_LOYALTY_BRAND)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setAllowedLoyaltyBrand(List<String> allowedLoyaltyBrand) {
    this.allowedLoyaltyBrand = allowedLoyaltyBrand;
  }


  public CardAcquisitionTransaction loyaltyHandling(LoyaltyHandling loyaltyHandling) {
    this.loyaltyHandling = loyaltyHandling;
    return this;
  }

   /**
   * Get loyaltyHandling
   * @return loyaltyHandling
  **/
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_LOYALTY_HANDLING)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public LoyaltyHandling getLoyaltyHandling() {
    return loyaltyHandling;
  }


 /**
  * loyaltyHandling
  *
  * @param loyaltyHandling
  */ 
  @JsonProperty(JSON_PROPERTY_LOYALTY_HANDLING)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setLoyaltyHandling(LoyaltyHandling loyaltyHandling) {
    this.loyaltyHandling = loyaltyHandling;
  }


  public CardAcquisitionTransaction customerLanguage(String customerLanguage) {
    this.customerLanguage = customerLanguage;
    return this;
  }

   /**
   * Get customerLanguage
   * @return customerLanguage
  **/
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_CUSTOMER_LANGUAGE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getCustomerLanguage() {
    return customerLanguage;
  }


 /**
  * customerLanguage
  *
  * @param customerLanguage
  */ 
  @JsonProperty(JSON_PROPERTY_CUSTOMER_LANGUAGE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setCustomerLanguage(String customerLanguage) {
    this.customerLanguage = customerLanguage;
  }


  public CardAcquisitionTransaction forceEntryMode(List<ForceEntryModeEnum> forceEntryMode) {
    this.forceEntryMode = forceEntryMode;
    return this;
  }

  public CardAcquisitionTransaction addForceEntryModeItem(ForceEntryModeEnum forceEntryModeItem) {
    if (this.forceEntryMode == null) {
      this.forceEntryMode = new ArrayList<>();
    }
    this.forceEntryMode.add(forceEntryModeItem);
    return this;
  }

   /**
   * Get forceEntryMode
   * @return forceEntryMode
  **/
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_FORCE_ENTRY_MODE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public List<ForceEntryModeEnum> getForceEntryMode() {
    return forceEntryMode;
  }


 /**
  * forceEntryMode
  *
  * @param forceEntryMode
  */ 
  @JsonProperty(JSON_PROPERTY_FORCE_ENTRY_MODE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setForceEntryMode(List<ForceEntryModeEnum> forceEntryMode) {
    this.forceEntryMode = forceEntryMode;
  }


  public CardAcquisitionTransaction forceCustomerSelectionFlag(Boolean forceCustomerSelectionFlag) {
    this.forceCustomerSelectionFlag = forceCustomerSelectionFlag;
    return this;
  }

   /**
   * Get forceCustomerSelectionFlag
   * @return forceCustomerSelectionFlag
  **/
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_FORCE_CUSTOMER_SELECTION_FLAG)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Boolean getForceCustomerSelectionFlag() {
    return forceCustomerSelectionFlag;
  }


 /**
  * forceCustomerSelectionFlag
  *
  * @param forceCustomerSelectionFlag
  */ 
  @JsonProperty(JSON_PROPERTY_FORCE_CUSTOMER_SELECTION_FLAG)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setForceCustomerSelectionFlag(Boolean forceCustomerSelectionFlag) {
    this.forceCustomerSelectionFlag = forceCustomerSelectionFlag;
  }


  public CardAcquisitionTransaction totalAmount(BigDecimal totalAmount) {
    this.totalAmount = totalAmount;
    return this;
  }

   /**
   * Get totalAmount
   * minimum: 0.0
   * maximum: 99999999.999999
   * @return totalAmount
  **/
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_TOTAL_AMOUNT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public BigDecimal getTotalAmount() {
    return totalAmount;
  }


 /**
  * totalAmount
  *
  * @param totalAmount
  */ 
  @JsonProperty(JSON_PROPERTY_TOTAL_AMOUNT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setTotalAmount(BigDecimal totalAmount) {
    this.totalAmount = totalAmount;
  }


  public CardAcquisitionTransaction paymentType(PaymentType paymentType) {
    this.paymentType = paymentType;
    return this;
  }

   /**
   * Get paymentType
   * @return paymentType
  **/
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_PAYMENT_TYPE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public PaymentType getPaymentType() {
    return paymentType;
  }


 /**
  * paymentType
  *
  * @param paymentType
  */ 
  @JsonProperty(JSON_PROPERTY_PAYMENT_TYPE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setPaymentType(PaymentType paymentType) {
    this.paymentType = paymentType;
  }


  public CardAcquisitionTransaction cashBackFlag(Boolean cashBackFlag) {
    this.cashBackFlag = cashBackFlag;
    return this;
  }

   /**
   * Get cashBackFlag
   * @return cashBackFlag
  **/
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_CASH_BACK_FLAG)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Boolean getCashBackFlag() {
    return cashBackFlag;
  }


 /**
  * cashBackFlag
  *
  * @param cashBackFlag
  */ 
  @JsonProperty(JSON_PROPERTY_CASH_BACK_FLAG)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setCashBackFlag(Boolean cashBackFlag) {
    this.cashBackFlag = cashBackFlag;
  }


  /**
   * Return true if this CardAcquisitionTransaction object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    CardAcquisitionTransaction cardAcquisitionTransaction = (CardAcquisitionTransaction) o;
    return Objects.equals(this.allowedPaymentBrand, cardAcquisitionTransaction.allowedPaymentBrand) &&
        Objects.equals(this.allowedLoyaltyBrand, cardAcquisitionTransaction.allowedLoyaltyBrand) &&
        Objects.equals(this.loyaltyHandling, cardAcquisitionTransaction.loyaltyHandling) &&
        Objects.equals(this.customerLanguage, cardAcquisitionTransaction.customerLanguage) &&
        Objects.equals(this.forceEntryMode, cardAcquisitionTransaction.forceEntryMode) &&
        Objects.equals(this.forceCustomerSelectionFlag, cardAcquisitionTransaction.forceCustomerSelectionFlag) &&
        Objects.equals(this.totalAmount, cardAcquisitionTransaction.totalAmount) &&
        Objects.equals(this.paymentType, cardAcquisitionTransaction.paymentType) &&
        Objects.equals(this.cashBackFlag, cardAcquisitionTransaction.cashBackFlag);
  }

  @Override
  public int hashCode() {
    return Objects.hash(allowedPaymentBrand, allowedLoyaltyBrand, loyaltyHandling, customerLanguage, forceEntryMode, forceCustomerSelectionFlag, totalAmount, paymentType, cashBackFlag);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class CardAcquisitionTransaction {\n");
    sb.append("    allowedPaymentBrand: ").append(toIndentedString(allowedPaymentBrand)).append("\n");
    sb.append("    allowedLoyaltyBrand: ").append(toIndentedString(allowedLoyaltyBrand)).append("\n");
    sb.append("    loyaltyHandling: ").append(toIndentedString(loyaltyHandling)).append("\n");
    sb.append("    customerLanguage: ").append(toIndentedString(customerLanguage)).append("\n");
    sb.append("    forceEntryMode: ").append(toIndentedString(forceEntryMode)).append("\n");
    sb.append("    forceCustomerSelectionFlag: ").append(toIndentedString(forceCustomerSelectionFlag)).append("\n");
    sb.append("    totalAmount: ").append(toIndentedString(totalAmount)).append("\n");
    sb.append("    paymentType: ").append(toIndentedString(paymentType)).append("\n");
    sb.append("    cashBackFlag: ").append(toIndentedString(cashBackFlag)).append("\n");
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
   * Create an instance of CardAcquisitionTransaction given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of CardAcquisitionTransaction
   * @throws JsonProcessingException if the JSON string is invalid with respect to CardAcquisitionTransaction
   */
  public static CardAcquisitionTransaction fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, CardAcquisitionTransaction.class);
  }
/**
  * Convert an instance of CardAcquisitionTransaction to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}
