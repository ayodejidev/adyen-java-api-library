/*
 * Adyen Payment API
 *
 * The version of the OpenAPI document: 68
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.adyen.model.payment;

import java.util.Objects;
import java.util.Arrays;
import java.util.Map;
import java.util.HashMap;
import com.adyen.model.payment.Amount;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.annotation.JsonValue;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import java.time.OffsetDateTime;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.core.JsonProcessingException;


/**
 * MerchantRiskIndicator
 */
@JsonPropertyOrder({
  MerchantRiskIndicator.JSON_PROPERTY_ADDRESS_MATCH,
  MerchantRiskIndicator.JSON_PROPERTY_DELIVERY_ADDRESS_INDICATOR,
  MerchantRiskIndicator.JSON_PROPERTY_DELIVERY_EMAIL,
  MerchantRiskIndicator.JSON_PROPERTY_DELIVERY_EMAIL_ADDRESS,
  MerchantRiskIndicator.JSON_PROPERTY_DELIVERY_TIMEFRAME,
  MerchantRiskIndicator.JSON_PROPERTY_GIFT_CARD_AMOUNT,
  MerchantRiskIndicator.JSON_PROPERTY_GIFT_CARD_COUNT,
  MerchantRiskIndicator.JSON_PROPERTY_GIFT_CARD_CURR,
  MerchantRiskIndicator.JSON_PROPERTY_PRE_ORDER_DATE,
  MerchantRiskIndicator.JSON_PROPERTY_PRE_ORDER_PURCHASE,
  MerchantRiskIndicator.JSON_PROPERTY_PRE_ORDER_PURCHASE_IND,
  MerchantRiskIndicator.JSON_PROPERTY_REORDER_ITEMS,
  MerchantRiskIndicator.JSON_PROPERTY_REORDER_ITEMS_IND,
  MerchantRiskIndicator.JSON_PROPERTY_SHIP_INDICATOR
})

public class MerchantRiskIndicator {
  public static final String JSON_PROPERTY_ADDRESS_MATCH = "addressMatch";
  private Boolean addressMatch;

  /**
   * Indicator regarding the delivery address. Allowed values: * &#x60;shipToBillingAddress&#x60; * &#x60;shipToVerifiedAddress&#x60; * &#x60;shipToNewAddress&#x60; * &#x60;shipToStore&#x60; * &#x60;digitalGoods&#x60; * &#x60;goodsNotShipped&#x60; * &#x60;other&#x60;
   */
  public enum DeliveryAddressIndicatorEnum {
    SHIPTOBILLINGADDRESS("shipToBillingAddress"),
    
    SHIPTOVERIFIEDADDRESS("shipToVerifiedAddress"),
    
    SHIPTONEWADDRESS("shipToNewAddress"),
    
    SHIPTOSTORE("shipToStore"),
    
    DIGITALGOODS("digitalGoods"),
    
    GOODSNOTSHIPPED("goodsNotShipped"),
    
    OTHER("other");

    private String value;

    DeliveryAddressIndicatorEnum(String value) {
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
    public static DeliveryAddressIndicatorEnum fromValue(String value) {
      for (DeliveryAddressIndicatorEnum b : DeliveryAddressIndicatorEnum.values()) {
        if (b.value.equals(value)) {
          return b;
        }
      }
      throw new IllegalArgumentException("Unexpected value '" + value + "'");
    }
  }

  public static final String JSON_PROPERTY_DELIVERY_ADDRESS_INDICATOR = "deliveryAddressIndicator";
  private DeliveryAddressIndicatorEnum deliveryAddressIndicator;

  public static final String JSON_PROPERTY_DELIVERY_EMAIL = "deliveryEmail";
  @Deprecated // deprecated since Adyen Payment API v68: Use `deliveryEmailAddress` instead.
  private String deliveryEmail;

  public static final String JSON_PROPERTY_DELIVERY_EMAIL_ADDRESS = "deliveryEmailAddress";
  private String deliveryEmailAddress;

  /**
   * The estimated delivery time for the shopper to receive the goods. Allowed values: * &#x60;electronicDelivery&#x60; * &#x60;sameDayShipping&#x60; * &#x60;overnightShipping&#x60; * &#x60;twoOrMoreDaysShipping&#x60;
   */
  public enum DeliveryTimeframeEnum {
    ELECTRONICDELIVERY("electronicDelivery"),
    
    SAMEDAYSHIPPING("sameDayShipping"),
    
    OVERNIGHTSHIPPING("overnightShipping"),
    
    TWOORMOREDAYSSHIPPING("twoOrMoreDaysShipping");

    private String value;

    DeliveryTimeframeEnum(String value) {
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
    public static DeliveryTimeframeEnum fromValue(String value) {
      for (DeliveryTimeframeEnum b : DeliveryTimeframeEnum.values()) {
        if (b.value.equals(value)) {
          return b;
        }
      }
      throw new IllegalArgumentException("Unexpected value '" + value + "'");
    }
  }

  public static final String JSON_PROPERTY_DELIVERY_TIMEFRAME = "deliveryTimeframe";
  private DeliveryTimeframeEnum deliveryTimeframe;

  public static final String JSON_PROPERTY_GIFT_CARD_AMOUNT = "giftCardAmount";
  private Amount giftCardAmount;

  public static final String JSON_PROPERTY_GIFT_CARD_COUNT = "giftCardCount";
  private Integer giftCardCount;

  public static final String JSON_PROPERTY_GIFT_CARD_CURR = "giftCardCurr";
  private String giftCardCurr;

  public static final String JSON_PROPERTY_PRE_ORDER_DATE = "preOrderDate";
  private OffsetDateTime preOrderDate;

  public static final String JSON_PROPERTY_PRE_ORDER_PURCHASE = "preOrderPurchase";
  private Boolean preOrderPurchase;

  public static final String JSON_PROPERTY_PRE_ORDER_PURCHASE_IND = "preOrderPurchaseInd";
  private String preOrderPurchaseInd;

  public static final String JSON_PROPERTY_REORDER_ITEMS = "reorderItems";
  private Boolean reorderItems;

  public static final String JSON_PROPERTY_REORDER_ITEMS_IND = "reorderItemsInd";
  private String reorderItemsInd;

  public static final String JSON_PROPERTY_SHIP_INDICATOR = "shipIndicator";
  private String shipIndicator;

  public MerchantRiskIndicator() { 
  }

  /**
   * Whether the chosen delivery address is identical to the billing address.
   *
   * @param addressMatch
   * @return the current {@code MerchantRiskIndicator} instance, allowing for method chaining
   */
  public MerchantRiskIndicator addressMatch(Boolean addressMatch) {
    this.addressMatch = addressMatch;
    return this;
  }

  /**
   * Whether the chosen delivery address is identical to the billing address.
   * @return addressMatch
   */
  @ApiModelProperty(value = "Whether the chosen delivery address is identical to the billing address.")
  @JsonProperty(JSON_PROPERTY_ADDRESS_MATCH)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public Boolean getAddressMatch() {
    return addressMatch;
  }

  /**
   * Whether the chosen delivery address is identical to the billing address.
   *
   * @param addressMatch
   */ 
  @JsonProperty(JSON_PROPERTY_ADDRESS_MATCH)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setAddressMatch(Boolean addressMatch) {
    this.addressMatch = addressMatch;
  }

  /**
   * Indicator regarding the delivery address. Allowed values: * &#x60;shipToBillingAddress&#x60; * &#x60;shipToVerifiedAddress&#x60; * &#x60;shipToNewAddress&#x60; * &#x60;shipToStore&#x60; * &#x60;digitalGoods&#x60; * &#x60;goodsNotShipped&#x60; * &#x60;other&#x60;
   *
   * @param deliveryAddressIndicator
   * @return the current {@code MerchantRiskIndicator} instance, allowing for method chaining
   */
  public MerchantRiskIndicator deliveryAddressIndicator(DeliveryAddressIndicatorEnum deliveryAddressIndicator) {
    this.deliveryAddressIndicator = deliveryAddressIndicator;
    return this;
  }

  /**
   * Indicator regarding the delivery address. Allowed values: * &#x60;shipToBillingAddress&#x60; * &#x60;shipToVerifiedAddress&#x60; * &#x60;shipToNewAddress&#x60; * &#x60;shipToStore&#x60; * &#x60;digitalGoods&#x60; * &#x60;goodsNotShipped&#x60; * &#x60;other&#x60;
   * @return deliveryAddressIndicator
   */
  @ApiModelProperty(value = "Indicator regarding the delivery address. Allowed values: * `shipToBillingAddress` * `shipToVerifiedAddress` * `shipToNewAddress` * `shipToStore` * `digitalGoods` * `goodsNotShipped` * `other`")
  @JsonProperty(JSON_PROPERTY_DELIVERY_ADDRESS_INDICATOR)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public DeliveryAddressIndicatorEnum getDeliveryAddressIndicator() {
    return deliveryAddressIndicator;
  }

  /**
   * Indicator regarding the delivery address. Allowed values: * &#x60;shipToBillingAddress&#x60; * &#x60;shipToVerifiedAddress&#x60; * &#x60;shipToNewAddress&#x60; * &#x60;shipToStore&#x60; * &#x60;digitalGoods&#x60; * &#x60;goodsNotShipped&#x60; * &#x60;other&#x60;
   *
   * @param deliveryAddressIndicator
   */ 
  @JsonProperty(JSON_PROPERTY_DELIVERY_ADDRESS_INDICATOR)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setDeliveryAddressIndicator(DeliveryAddressIndicatorEnum deliveryAddressIndicator) {
    this.deliveryAddressIndicator = deliveryAddressIndicator;
  }

  /**
   * The delivery email address (for digital goods).
   *
   * @param deliveryEmail
   * @return the current {@code MerchantRiskIndicator} instance, allowing for method chaining
   *
   * @deprecated since Adyen Payment API v68
   * Use &#x60;deliveryEmailAddress&#x60; instead.
   */
  @Deprecated
  public MerchantRiskIndicator deliveryEmail(String deliveryEmail) {
    this.deliveryEmail = deliveryEmail;
    return this;
  }

  /**
   * The delivery email address (for digital goods).
   * @return deliveryEmail
   *
   * @deprecated since Adyen Payment API v68
   * Use &#x60;deliveryEmailAddress&#x60; instead.
   */
  @Deprecated
  @ApiModelProperty(value = "The delivery email address (for digital goods).")
  @JsonProperty(JSON_PROPERTY_DELIVERY_EMAIL)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getDeliveryEmail() {
    return deliveryEmail;
  }

  /**
   * The delivery email address (for digital goods).
   *
   * @param deliveryEmail
   *
   * @deprecated since Adyen Payment API v68
   * Use &#x60;deliveryEmailAddress&#x60; instead.
   */ 
  @Deprecated
  @JsonProperty(JSON_PROPERTY_DELIVERY_EMAIL)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setDeliveryEmail(String deliveryEmail) {
    this.deliveryEmail = deliveryEmail;
  }

  /**
   * For Electronic delivery, the email address to which the merchandise was delivered. Maximum length: 254 characters.
   *
   * @param deliveryEmailAddress
   * @return the current {@code MerchantRiskIndicator} instance, allowing for method chaining
   */
  public MerchantRiskIndicator deliveryEmailAddress(String deliveryEmailAddress) {
    this.deliveryEmailAddress = deliveryEmailAddress;
    return this;
  }

  /**
   * For Electronic delivery, the email address to which the merchandise was delivered. Maximum length: 254 characters.
   * @return deliveryEmailAddress
   */
  @ApiModelProperty(value = "For Electronic delivery, the email address to which the merchandise was delivered. Maximum length: 254 characters.")
  @JsonProperty(JSON_PROPERTY_DELIVERY_EMAIL_ADDRESS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getDeliveryEmailAddress() {
    return deliveryEmailAddress;
  }

  /**
   * For Electronic delivery, the email address to which the merchandise was delivered. Maximum length: 254 characters.
   *
   * @param deliveryEmailAddress
   */ 
  @JsonProperty(JSON_PROPERTY_DELIVERY_EMAIL_ADDRESS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setDeliveryEmailAddress(String deliveryEmailAddress) {
    this.deliveryEmailAddress = deliveryEmailAddress;
  }

  /**
   * The estimated delivery time for the shopper to receive the goods. Allowed values: * &#x60;electronicDelivery&#x60; * &#x60;sameDayShipping&#x60; * &#x60;overnightShipping&#x60; * &#x60;twoOrMoreDaysShipping&#x60;
   *
   * @param deliveryTimeframe
   * @return the current {@code MerchantRiskIndicator} instance, allowing for method chaining
   */
  public MerchantRiskIndicator deliveryTimeframe(DeliveryTimeframeEnum deliveryTimeframe) {
    this.deliveryTimeframe = deliveryTimeframe;
    return this;
  }

  /**
   * The estimated delivery time for the shopper to receive the goods. Allowed values: * &#x60;electronicDelivery&#x60; * &#x60;sameDayShipping&#x60; * &#x60;overnightShipping&#x60; * &#x60;twoOrMoreDaysShipping&#x60;
   * @return deliveryTimeframe
   */
  @ApiModelProperty(value = "The estimated delivery time for the shopper to receive the goods. Allowed values: * `electronicDelivery` * `sameDayShipping` * `overnightShipping` * `twoOrMoreDaysShipping`")
  @JsonProperty(JSON_PROPERTY_DELIVERY_TIMEFRAME)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public DeliveryTimeframeEnum getDeliveryTimeframe() {
    return deliveryTimeframe;
  }

  /**
   * The estimated delivery time for the shopper to receive the goods. Allowed values: * &#x60;electronicDelivery&#x60; * &#x60;sameDayShipping&#x60; * &#x60;overnightShipping&#x60; * &#x60;twoOrMoreDaysShipping&#x60;
   *
   * @param deliveryTimeframe
   */ 
  @JsonProperty(JSON_PROPERTY_DELIVERY_TIMEFRAME)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setDeliveryTimeframe(DeliveryTimeframeEnum deliveryTimeframe) {
    this.deliveryTimeframe = deliveryTimeframe;
  }

  /**
   * giftCardAmount
   *
   * @param giftCardAmount
   * @return the current {@code MerchantRiskIndicator} instance, allowing for method chaining
   */
  public MerchantRiskIndicator giftCardAmount(Amount giftCardAmount) {
    this.giftCardAmount = giftCardAmount;
    return this;
  }

  /**
   * giftCardAmount
   * @return giftCardAmount
   */
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_GIFT_CARD_AMOUNT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public Amount getGiftCardAmount() {
    return giftCardAmount;
  }

  /**
   * giftCardAmount
   *
   * @param giftCardAmount
   */ 
  @JsonProperty(JSON_PROPERTY_GIFT_CARD_AMOUNT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setGiftCardAmount(Amount giftCardAmount) {
    this.giftCardAmount = giftCardAmount;
  }

  /**
   * For prepaid or gift card purchase, total count of individual prepaid or gift cards/codes purchased.
   *
   * @param giftCardCount
   * @return the current {@code MerchantRiskIndicator} instance, allowing for method chaining
   */
  public MerchantRiskIndicator giftCardCount(Integer giftCardCount) {
    this.giftCardCount = giftCardCount;
    return this;
  }

  /**
   * For prepaid or gift card purchase, total count of individual prepaid or gift cards/codes purchased.
   * @return giftCardCount
   */
  @ApiModelProperty(value = "For prepaid or gift card purchase, total count of individual prepaid or gift cards/codes purchased.")
  @JsonProperty(JSON_PROPERTY_GIFT_CARD_COUNT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public Integer getGiftCardCount() {
    return giftCardCount;
  }

  /**
   * For prepaid or gift card purchase, total count of individual prepaid or gift cards/codes purchased.
   *
   * @param giftCardCount
   */ 
  @JsonProperty(JSON_PROPERTY_GIFT_CARD_COUNT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setGiftCardCount(Integer giftCardCount) {
    this.giftCardCount = giftCardCount;
  }

  /**
   * For prepaid or gift card purchase, [ISO 4217](https://www.iso.org/iso-4217-currency-codes.html) three-digit currency code of the gift card, other than those listed in Table A.5 of the EMVCo 3D Secure Protocol and Core Functions Specification.
   *
   * @param giftCardCurr
   * @return the current {@code MerchantRiskIndicator} instance, allowing for method chaining
   */
  public MerchantRiskIndicator giftCardCurr(String giftCardCurr) {
    this.giftCardCurr = giftCardCurr;
    return this;
  }

  /**
   * For prepaid or gift card purchase, [ISO 4217](https://www.iso.org/iso-4217-currency-codes.html) three-digit currency code of the gift card, other than those listed in Table A.5 of the EMVCo 3D Secure Protocol and Core Functions Specification.
   * @return giftCardCurr
   */
  @ApiModelProperty(value = "For prepaid or gift card purchase, [ISO 4217](https://www.iso.org/iso-4217-currency-codes.html) three-digit currency code of the gift card, other than those listed in Table A.5 of the EMVCo 3D Secure Protocol and Core Functions Specification.")
  @JsonProperty(JSON_PROPERTY_GIFT_CARD_CURR)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getGiftCardCurr() {
    return giftCardCurr;
  }

  /**
   * For prepaid or gift card purchase, [ISO 4217](https://www.iso.org/iso-4217-currency-codes.html) three-digit currency code of the gift card, other than those listed in Table A.5 of the EMVCo 3D Secure Protocol and Core Functions Specification.
   *
   * @param giftCardCurr
   */ 
  @JsonProperty(JSON_PROPERTY_GIFT_CARD_CURR)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setGiftCardCurr(String giftCardCurr) {
    this.giftCardCurr = giftCardCurr;
  }

  /**
   * For pre-order purchases, the expected date this product will be available to the shopper.
   *
   * @param preOrderDate
   * @return the current {@code MerchantRiskIndicator} instance, allowing for method chaining
   */
  public MerchantRiskIndicator preOrderDate(OffsetDateTime preOrderDate) {
    this.preOrderDate = preOrderDate;
    return this;
  }

  /**
   * For pre-order purchases, the expected date this product will be available to the shopper.
   * @return preOrderDate
   */
  @ApiModelProperty(value = "For pre-order purchases, the expected date this product will be available to the shopper.")
  @JsonProperty(JSON_PROPERTY_PRE_ORDER_DATE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public OffsetDateTime getPreOrderDate() {
    return preOrderDate;
  }

  /**
   * For pre-order purchases, the expected date this product will be available to the shopper.
   *
   * @param preOrderDate
   */ 
  @JsonProperty(JSON_PROPERTY_PRE_ORDER_DATE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setPreOrderDate(OffsetDateTime preOrderDate) {
    this.preOrderDate = preOrderDate;
  }

  /**
   * Indicator for whether this transaction is for pre-ordering a product.
   *
   * @param preOrderPurchase
   * @return the current {@code MerchantRiskIndicator} instance, allowing for method chaining
   */
  public MerchantRiskIndicator preOrderPurchase(Boolean preOrderPurchase) {
    this.preOrderPurchase = preOrderPurchase;
    return this;
  }

  /**
   * Indicator for whether this transaction is for pre-ordering a product.
   * @return preOrderPurchase
   */
  @ApiModelProperty(value = "Indicator for whether this transaction is for pre-ordering a product.")
  @JsonProperty(JSON_PROPERTY_PRE_ORDER_PURCHASE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public Boolean getPreOrderPurchase() {
    return preOrderPurchase;
  }

  /**
   * Indicator for whether this transaction is for pre-ordering a product.
   *
   * @param preOrderPurchase
   */ 
  @JsonProperty(JSON_PROPERTY_PRE_ORDER_PURCHASE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setPreOrderPurchase(Boolean preOrderPurchase) {
    this.preOrderPurchase = preOrderPurchase;
  }

  /**
   * Indicates whether Cardholder is placing an order for merchandise with a future availability or release date.
   *
   * @param preOrderPurchaseInd
   * @return the current {@code MerchantRiskIndicator} instance, allowing for method chaining
   */
  public MerchantRiskIndicator preOrderPurchaseInd(String preOrderPurchaseInd) {
    this.preOrderPurchaseInd = preOrderPurchaseInd;
    return this;
  }

  /**
   * Indicates whether Cardholder is placing an order for merchandise with a future availability or release date.
   * @return preOrderPurchaseInd
   */
  @ApiModelProperty(value = "Indicates whether Cardholder is placing an order for merchandise with a future availability or release date.")
  @JsonProperty(JSON_PROPERTY_PRE_ORDER_PURCHASE_IND)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getPreOrderPurchaseInd() {
    return preOrderPurchaseInd;
  }

  /**
   * Indicates whether Cardholder is placing an order for merchandise with a future availability or release date.
   *
   * @param preOrderPurchaseInd
   */ 
  @JsonProperty(JSON_PROPERTY_PRE_ORDER_PURCHASE_IND)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setPreOrderPurchaseInd(String preOrderPurchaseInd) {
    this.preOrderPurchaseInd = preOrderPurchaseInd;
  }

  /**
   * Indicator for whether the shopper has already purchased the same items in the past.
   *
   * @param reorderItems
   * @return the current {@code MerchantRiskIndicator} instance, allowing for method chaining
   */
  public MerchantRiskIndicator reorderItems(Boolean reorderItems) {
    this.reorderItems = reorderItems;
    return this;
  }

  /**
   * Indicator for whether the shopper has already purchased the same items in the past.
   * @return reorderItems
   */
  @ApiModelProperty(value = "Indicator for whether the shopper has already purchased the same items in the past.")
  @JsonProperty(JSON_PROPERTY_REORDER_ITEMS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public Boolean getReorderItems() {
    return reorderItems;
  }

  /**
   * Indicator for whether the shopper has already purchased the same items in the past.
   *
   * @param reorderItems
   */ 
  @JsonProperty(JSON_PROPERTY_REORDER_ITEMS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setReorderItems(Boolean reorderItems) {
    this.reorderItems = reorderItems;
  }

  /**
   * Indicates whether the cardholder is reordering previously purchased merchandise.
   *
   * @param reorderItemsInd
   * @return the current {@code MerchantRiskIndicator} instance, allowing for method chaining
   */
  public MerchantRiskIndicator reorderItemsInd(String reorderItemsInd) {
    this.reorderItemsInd = reorderItemsInd;
    return this;
  }

  /**
   * Indicates whether the cardholder is reordering previously purchased merchandise.
   * @return reorderItemsInd
   */
  @ApiModelProperty(value = "Indicates whether the cardholder is reordering previously purchased merchandise.")
  @JsonProperty(JSON_PROPERTY_REORDER_ITEMS_IND)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getReorderItemsInd() {
    return reorderItemsInd;
  }

  /**
   * Indicates whether the cardholder is reordering previously purchased merchandise.
   *
   * @param reorderItemsInd
   */ 
  @JsonProperty(JSON_PROPERTY_REORDER_ITEMS_IND)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setReorderItemsInd(String reorderItemsInd) {
    this.reorderItemsInd = reorderItemsInd;
  }

  /**
   * Indicates shipping method chosen for the transaction.
   *
   * @param shipIndicator
   * @return the current {@code MerchantRiskIndicator} instance, allowing for method chaining
   */
  public MerchantRiskIndicator shipIndicator(String shipIndicator) {
    this.shipIndicator = shipIndicator;
    return this;
  }

  /**
   * Indicates shipping method chosen for the transaction.
   * @return shipIndicator
   */
  @ApiModelProperty(value = "Indicates shipping method chosen for the transaction.")
  @JsonProperty(JSON_PROPERTY_SHIP_INDICATOR)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getShipIndicator() {
    return shipIndicator;
  }

  /**
   * Indicates shipping method chosen for the transaction.
   *
   * @param shipIndicator
   */ 
  @JsonProperty(JSON_PROPERTY_SHIP_INDICATOR)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setShipIndicator(String shipIndicator) {
    this.shipIndicator = shipIndicator;
  }

  /**
   * Return true if this MerchantRiskIndicator object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    MerchantRiskIndicator merchantRiskIndicator = (MerchantRiskIndicator) o;
    return Objects.equals(this.addressMatch, merchantRiskIndicator.addressMatch) &&
        Objects.equals(this.deliveryAddressIndicator, merchantRiskIndicator.deliveryAddressIndicator) &&
        Objects.equals(this.deliveryEmail, merchantRiskIndicator.deliveryEmail) &&
        Objects.equals(this.deliveryEmailAddress, merchantRiskIndicator.deliveryEmailAddress) &&
        Objects.equals(this.deliveryTimeframe, merchantRiskIndicator.deliveryTimeframe) &&
        Objects.equals(this.giftCardAmount, merchantRiskIndicator.giftCardAmount) &&
        Objects.equals(this.giftCardCount, merchantRiskIndicator.giftCardCount) &&
        Objects.equals(this.giftCardCurr, merchantRiskIndicator.giftCardCurr) &&
        Objects.equals(this.preOrderDate, merchantRiskIndicator.preOrderDate) &&
        Objects.equals(this.preOrderPurchase, merchantRiskIndicator.preOrderPurchase) &&
        Objects.equals(this.preOrderPurchaseInd, merchantRiskIndicator.preOrderPurchaseInd) &&
        Objects.equals(this.reorderItems, merchantRiskIndicator.reorderItems) &&
        Objects.equals(this.reorderItemsInd, merchantRiskIndicator.reorderItemsInd) &&
        Objects.equals(this.shipIndicator, merchantRiskIndicator.shipIndicator);
  }

  @Override
  public int hashCode() {
    return Objects.hash(addressMatch, deliveryAddressIndicator, deliveryEmail, deliveryEmailAddress, deliveryTimeframe, giftCardAmount, giftCardCount, giftCardCurr, preOrderDate, preOrderPurchase, preOrderPurchaseInd, reorderItems, reorderItemsInd, shipIndicator);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class MerchantRiskIndicator {\n");
    sb.append("    addressMatch: ").append(toIndentedString(addressMatch)).append("\n");
    sb.append("    deliveryAddressIndicator: ").append(toIndentedString(deliveryAddressIndicator)).append("\n");
    sb.append("    deliveryEmail: ").append(toIndentedString(deliveryEmail)).append("\n");
    sb.append("    deliveryEmailAddress: ").append(toIndentedString(deliveryEmailAddress)).append("\n");
    sb.append("    deliveryTimeframe: ").append(toIndentedString(deliveryTimeframe)).append("\n");
    sb.append("    giftCardAmount: ").append(toIndentedString(giftCardAmount)).append("\n");
    sb.append("    giftCardCount: ").append(toIndentedString(giftCardCount)).append("\n");
    sb.append("    giftCardCurr: ").append(toIndentedString(giftCardCurr)).append("\n");
    sb.append("    preOrderDate: ").append(toIndentedString(preOrderDate)).append("\n");
    sb.append("    preOrderPurchase: ").append(toIndentedString(preOrderPurchase)).append("\n");
    sb.append("    preOrderPurchaseInd: ").append(toIndentedString(preOrderPurchaseInd)).append("\n");
    sb.append("    reorderItems: ").append(toIndentedString(reorderItems)).append("\n");
    sb.append("    reorderItemsInd: ").append(toIndentedString(reorderItemsInd)).append("\n");
    sb.append("    shipIndicator: ").append(toIndentedString(shipIndicator)).append("\n");
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
   * Create an instance of MerchantRiskIndicator given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of MerchantRiskIndicator
   * @throws JsonProcessingException if the JSON string is invalid with respect to MerchantRiskIndicator
   */
  public static MerchantRiskIndicator fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, MerchantRiskIndicator.class);
  }
/**
  * Convert an instance of MerchantRiskIndicator to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}
