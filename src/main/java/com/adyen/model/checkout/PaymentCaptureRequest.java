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
import com.adyen.model.checkout.Amount;
import com.adyen.model.checkout.ApplicationInfo;
import com.adyen.model.checkout.LineItem;
import com.adyen.model.checkout.PlatformChargebackLogic;
import com.adyen.model.checkout.Split;
import com.adyen.model.checkout.SubMerchantInfo;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.annotation.JsonValue;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import java.util.ArrayList;
import java.util.List;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.core.JsonProcessingException;


/**
 * PaymentCaptureRequest
 */
@JsonPropertyOrder({
  PaymentCaptureRequest.JSON_PROPERTY_AMOUNT,
  PaymentCaptureRequest.JSON_PROPERTY_APPLICATION_INFO,
  PaymentCaptureRequest.JSON_PROPERTY_LINE_ITEMS,
  PaymentCaptureRequest.JSON_PROPERTY_MERCHANT_ACCOUNT,
  PaymentCaptureRequest.JSON_PROPERTY_PLATFORM_CHARGEBACK_LOGIC,
  PaymentCaptureRequest.JSON_PROPERTY_REFERENCE,
  PaymentCaptureRequest.JSON_PROPERTY_SPLITS,
  PaymentCaptureRequest.JSON_PROPERTY_SUB_MERCHANTS
})

public class PaymentCaptureRequest {
  public static final String JSON_PROPERTY_AMOUNT = "amount";
  private Amount amount;

  public static final String JSON_PROPERTY_APPLICATION_INFO = "applicationInfo";
  private ApplicationInfo applicationInfo;

  public static final String JSON_PROPERTY_LINE_ITEMS = "lineItems";
  private List<LineItem> lineItems = null;

  public static final String JSON_PROPERTY_MERCHANT_ACCOUNT = "merchantAccount";
  private String merchantAccount;

  public static final String JSON_PROPERTY_PLATFORM_CHARGEBACK_LOGIC = "platformChargebackLogic";
  private PlatformChargebackLogic platformChargebackLogic;

  public static final String JSON_PROPERTY_REFERENCE = "reference";
  private String reference;

  public static final String JSON_PROPERTY_SPLITS = "splits";
  private List<Split> splits = null;

  public static final String JSON_PROPERTY_SUB_MERCHANTS = "subMerchants";
  private List<SubMerchantInfo> subMerchants = null;

  public PaymentCaptureRequest() { 
  }

  public PaymentCaptureRequest amount(Amount amount) {
    this.amount = amount;
    return this;
  }

   /**
   * Get amount
   * @return amount
  **/
  @ApiModelProperty(required = true, value = "")
  @JsonProperty(JSON_PROPERTY_AMOUNT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Amount getAmount() {
    return amount;
  }


 /**
  * amount
  *
  * @param amount
  */ 
  @JsonProperty(JSON_PROPERTY_AMOUNT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setAmount(Amount amount) {
    this.amount = amount;
  }


  public PaymentCaptureRequest applicationInfo(ApplicationInfo applicationInfo) {
    this.applicationInfo = applicationInfo;
    return this;
  }

   /**
   * Get applicationInfo
   * @return applicationInfo
  **/
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_APPLICATION_INFO)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public ApplicationInfo getApplicationInfo() {
    return applicationInfo;
  }


 /**
  * applicationInfo
  *
  * @param applicationInfo
  */ 
  @JsonProperty(JSON_PROPERTY_APPLICATION_INFO)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setApplicationInfo(ApplicationInfo applicationInfo) {
    this.applicationInfo = applicationInfo;
  }


  public PaymentCaptureRequest lineItems(List<LineItem> lineItems) {
    this.lineItems = lineItems;
    return this;
  }

  public PaymentCaptureRequest addLineItemsItem(LineItem lineItemsItem) {
    if (this.lineItems == null) {
      this.lineItems = new ArrayList<>();
    }
    this.lineItems.add(lineItemsItem);
    return this;
  }

   /**
   * Price and product information of the refunded items, required for [partial refunds](https://docs.adyen.com/online-payments/refund#refund-a-payment). &gt; This field is required for partial refunds with 3x 4x Oney, Affirm, Afterpay, Atome, Clearpay, Klarna, Ratepay, Walley, and Zip.
   * @return lineItems
  **/
  @ApiModelProperty(value = "Price and product information of the refunded items, required for [partial refunds](https://docs.adyen.com/online-payments/refund#refund-a-payment). > This field is required for partial refunds with 3x 4x Oney, Affirm, Afterpay, Atome, Clearpay, Klarna, Ratepay, Walley, and Zip.")
  @JsonProperty(JSON_PROPERTY_LINE_ITEMS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public List<LineItem> getLineItems() {
    return lineItems;
  }


 /**
  * Price and product information of the refunded items, required for [partial refunds](https://docs.adyen.com/online-payments/refund#refund-a-payment). &gt; This field is required for partial refunds with 3x 4x Oney, Affirm, Afterpay, Atome, Clearpay, Klarna, Ratepay, Walley, and Zip.
  *
  * @param lineItems
  */ 
  @JsonProperty(JSON_PROPERTY_LINE_ITEMS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setLineItems(List<LineItem> lineItems) {
    this.lineItems = lineItems;
  }


  public PaymentCaptureRequest merchantAccount(String merchantAccount) {
    this.merchantAccount = merchantAccount;
    return this;
  }

   /**
   * The merchant account that is used to process the payment.
   * @return merchantAccount
  **/
  @ApiModelProperty(required = true, value = "The merchant account that is used to process the payment.")
  @JsonProperty(JSON_PROPERTY_MERCHANT_ACCOUNT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getMerchantAccount() {
    return merchantAccount;
  }


 /**
  * The merchant account that is used to process the payment.
  *
  * @param merchantAccount
  */ 
  @JsonProperty(JSON_PROPERTY_MERCHANT_ACCOUNT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setMerchantAccount(String merchantAccount) {
    this.merchantAccount = merchantAccount;
  }


  public PaymentCaptureRequest platformChargebackLogic(PlatformChargebackLogic platformChargebackLogic) {
    this.platformChargebackLogic = platformChargebackLogic;
    return this;
  }

   /**
   * Get platformChargebackLogic
   * @return platformChargebackLogic
  **/
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_PLATFORM_CHARGEBACK_LOGIC)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public PlatformChargebackLogic getPlatformChargebackLogic() {
    return platformChargebackLogic;
  }


 /**
  * platformChargebackLogic
  *
  * @param platformChargebackLogic
  */ 
  @JsonProperty(JSON_PROPERTY_PLATFORM_CHARGEBACK_LOGIC)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setPlatformChargebackLogic(PlatformChargebackLogic platformChargebackLogic) {
    this.platformChargebackLogic = platformChargebackLogic;
  }


  public PaymentCaptureRequest reference(String reference) {
    this.reference = reference;
    return this;
  }

   /**
   * Your reference for the capture request. Maximum length: 80 characters.
   * @return reference
  **/
  @ApiModelProperty(value = "Your reference for the capture request. Maximum length: 80 characters.")
  @JsonProperty(JSON_PROPERTY_REFERENCE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getReference() {
    return reference;
  }


 /**
  * Your reference for the capture request. Maximum length: 80 characters.
  *
  * @param reference
  */ 
  @JsonProperty(JSON_PROPERTY_REFERENCE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setReference(String reference) {
    this.reference = reference;
  }


  public PaymentCaptureRequest splits(List<Split> splits) {
    this.splits = splits;
    return this;
  }

  public PaymentCaptureRequest addSplitsItem(Split splitsItem) {
    if (this.splits == null) {
      this.splits = new ArrayList<>();
    }
    this.splits.add(splitsItem);
    return this;
  }

   /**
   * An array of objects specifying how the amount should be split between accounts when using Adyen for Platforms. For more information, see how to process payments for [marketplaces](https://docs.adyen.com/marketplaces/split-payments) or [platforms](https://docs.adyen.com/platforms/online-payments/split-payments/).
   * @return splits
  **/
  @ApiModelProperty(value = "An array of objects specifying how the amount should be split between accounts when using Adyen for Platforms. For more information, see how to process payments for [marketplaces](https://docs.adyen.com/marketplaces/split-payments) or [platforms](https://docs.adyen.com/platforms/online-payments/split-payments/).")
  @JsonProperty(JSON_PROPERTY_SPLITS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public List<Split> getSplits() {
    return splits;
  }


 /**
  * An array of objects specifying how the amount should be split between accounts when using Adyen for Platforms. For more information, see how to process payments for [marketplaces](https://docs.adyen.com/marketplaces/split-payments) or [platforms](https://docs.adyen.com/platforms/online-payments/split-payments/).
  *
  * @param splits
  */ 
  @JsonProperty(JSON_PROPERTY_SPLITS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setSplits(List<Split> splits) {
    this.splits = splits;
  }


  public PaymentCaptureRequest subMerchants(List<SubMerchantInfo> subMerchants) {
    this.subMerchants = subMerchants;
    return this;
  }

  public PaymentCaptureRequest addSubMerchantsItem(SubMerchantInfo subMerchantsItem) {
    if (this.subMerchants == null) {
      this.subMerchants = new ArrayList<>();
    }
    this.subMerchants.add(subMerchantsItem);
    return this;
  }

   /**
   * A List of sub-merchants.
   * @return subMerchants
  **/
  @ApiModelProperty(value = "A List of sub-merchants.")
  @JsonProperty(JSON_PROPERTY_SUB_MERCHANTS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public List<SubMerchantInfo> getSubMerchants() {
    return subMerchants;
  }


 /**
  * A List of sub-merchants.
  *
  * @param subMerchants
  */ 
  @JsonProperty(JSON_PROPERTY_SUB_MERCHANTS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setSubMerchants(List<SubMerchantInfo> subMerchants) {
    this.subMerchants = subMerchants;
  }


  /**
   * Return true if this PaymentCaptureRequest object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    PaymentCaptureRequest paymentCaptureRequest = (PaymentCaptureRequest) o;
    return Objects.equals(this.amount, paymentCaptureRequest.amount) &&
        Objects.equals(this.applicationInfo, paymentCaptureRequest.applicationInfo) &&
        Objects.equals(this.lineItems, paymentCaptureRequest.lineItems) &&
        Objects.equals(this.merchantAccount, paymentCaptureRequest.merchantAccount) &&
        Objects.equals(this.platformChargebackLogic, paymentCaptureRequest.platformChargebackLogic) &&
        Objects.equals(this.reference, paymentCaptureRequest.reference) &&
        Objects.equals(this.splits, paymentCaptureRequest.splits) &&
        Objects.equals(this.subMerchants, paymentCaptureRequest.subMerchants);
  }

  @Override
  public int hashCode() {
    return Objects.hash(amount, applicationInfo, lineItems, merchantAccount, platformChargebackLogic, reference, splits, subMerchants);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class PaymentCaptureRequest {\n");
    sb.append("    amount: ").append(toIndentedString(amount)).append("\n");
    sb.append("    applicationInfo: ").append(toIndentedString(applicationInfo)).append("\n");
    sb.append("    lineItems: ").append(toIndentedString(lineItems)).append("\n");
    sb.append("    merchantAccount: ").append(toIndentedString(merchantAccount)).append("\n");
    sb.append("    platformChargebackLogic: ").append(toIndentedString(platformChargebackLogic)).append("\n");
    sb.append("    reference: ").append(toIndentedString(reference)).append("\n");
    sb.append("    splits: ").append(toIndentedString(splits)).append("\n");
    sb.append("    subMerchants: ").append(toIndentedString(subMerchants)).append("\n");
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
   * Create an instance of PaymentCaptureRequest given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of PaymentCaptureRequest
   * @throws JsonProcessingException if the JSON string is invalid with respect to PaymentCaptureRequest
   */
  public static PaymentCaptureRequest fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, PaymentCaptureRequest.class);
  }
/**
  * Convert an instance of PaymentCaptureRequest to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}

