/*
 * Configuration API
 *
 * The version of the OpenAPI document: 2
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.adyen.model.balanceplatform;

import java.util.Objects;
import java.util.Arrays;
import java.util.Map;
import java.util.HashMap;
import com.adyen.model.balanceplatform.TransferRouteRequirementsInner;
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
 * TransferRoute
 */
@JsonPropertyOrder({
  TransferRoute.JSON_PROPERTY_CATEGORY,
  TransferRoute.JSON_PROPERTY_COUNTRY,
  TransferRoute.JSON_PROPERTY_CURRENCY,
  TransferRoute.JSON_PROPERTY_PRIORITY,
  TransferRoute.JSON_PROPERTY_REQUIREMENTS
})

public class TransferRoute {
  /**
   *  The type of transfer.   Possible values:    - **bank**: Transfer to a [transfer instrument](https://docs.adyen.com/api-explorer/#/legalentity/latest/post/transferInstruments__resParam_id) or a bank account. 
   */
  public enum CategoryEnum {
    BANK("bank"),
    
    CARD("card"),
    
    GRANTS("grants"),
    
    INTERNAL("internal"),
    
    ISSUEDCARD("issuedCard"),
    
    MIGRATION("migration"),
    
    PLATFORMPAYMENT("platformPayment"),
    
    TOPUP("topUp"),
    
    UPGRADE("upgrade");

    private String value;

    CategoryEnum(String value) {
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
    public static CategoryEnum fromValue(String value) {
      for (CategoryEnum b : CategoryEnum.values()) {
        if (b.value.equals(value)) {
          return b;
        }
      }
      throw new IllegalArgumentException("Unexpected value '" + value + "'");
    }
  }

  public static final String JSON_PROPERTY_CATEGORY = "category";
  private CategoryEnum category;

  public static final String JSON_PROPERTY_COUNTRY = "country";
  private String country;

  public static final String JSON_PROPERTY_CURRENCY = "currency";
  private String currency;

  /**
   * The priority for the bank transfer. This sets the speed at which the transfer is sent and the fees that you have to pay. Possible values:  * **regular**: for normal, low-value transactions.  * **fast**: a faster way to transfer funds, but the fees are higher. Recommended for high-priority, low-value transactions.  * **wire**: the fastest way to transfer funds, but this has the highest fees. Recommended for high-priority, high-value transactions.  * **instant**: for instant funds transfers in [SEPA countries](https://www.ecb.europa.eu/paym/integration/retail/sepa/html/index.en.html).  * **crossBorder**: for high-value transfers to a recipient in a different country.  * **internal**: for transfers to an Adyen-issued business bank account (by bank account number/IBAN).
   */
  public enum PriorityEnum {
    CROSSBORDER("crossBorder"),
    
    FAST("fast"),
    
    INSTANT("instant"),
    
    INTERNAL("internal"),
    
    REGULAR("regular"),
    
    WIRE("wire");

    private String value;

    PriorityEnum(String value) {
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
    public static PriorityEnum fromValue(String value) {
      for (PriorityEnum b : PriorityEnum.values()) {
        if (b.value.equals(value)) {
          return b;
        }
      }
      throw new IllegalArgumentException("Unexpected value '" + value + "'");
    }
  }

  public static final String JSON_PROPERTY_PRIORITY = "priority";
  private PriorityEnum priority;

  public static final String JSON_PROPERTY_REQUIREMENTS = "requirements";
  private List<TransferRouteRequirementsInner> requirements = null;

  public TransferRoute() { 
  }

  /**
   *  The type of transfer.   Possible values:    - **bank**: Transfer to a [transfer instrument](https://docs.adyen.com/api-explorer/#/legalentity/latest/post/transferInstruments__resParam_id) or a bank account. 
   *
   * @param category
   * @return the current {@code TransferRoute} instance, allowing for method chaining
   */
  public TransferRoute category(CategoryEnum category) {
    this.category = category;
    return this;
  }

  /**
   *  The type of transfer.   Possible values:    - **bank**: Transfer to a [transfer instrument](https://docs.adyen.com/api-explorer/#/legalentity/latest/post/transferInstruments__resParam_id) or a bank account. 
   * @return category
   */
  @ApiModelProperty(value = " The type of transfer.   Possible values:    - **bank**: Transfer to a [transfer instrument](https://docs.adyen.com/api-explorer/#/legalentity/latest/post/transferInstruments__resParam_id) or a bank account. ")
  @JsonProperty(JSON_PROPERTY_CATEGORY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public CategoryEnum getCategory() {
    return category;
  }

  /**
   *  The type of transfer.   Possible values:    - **bank**: Transfer to a [transfer instrument](https://docs.adyen.com/api-explorer/#/legalentity/latest/post/transferInstruments__resParam_id) or a bank account. 
   *
   * @param category
   */ 
  @JsonProperty(JSON_PROPERTY_CATEGORY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setCategory(CategoryEnum category) {
    this.category = category;
  }

  /**
   * The two-character ISO-3166-1 alpha-2 country code of the counterparty. For example, **US** or **NL**.
   *
   * @param country
   * @return the current {@code TransferRoute} instance, allowing for method chaining
   */
  public TransferRoute country(String country) {
    this.country = country;
    return this;
  }

  /**
   * The two-character ISO-3166-1 alpha-2 country code of the counterparty. For example, **US** or **NL**.
   * @return country
   */
  @ApiModelProperty(value = "The two-character ISO-3166-1 alpha-2 country code of the counterparty. For example, **US** or **NL**.")
  @JsonProperty(JSON_PROPERTY_COUNTRY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getCountry() {
    return country;
  }

  /**
   * The two-character ISO-3166-1 alpha-2 country code of the counterparty. For example, **US** or **NL**.
   *
   * @param country
   */ 
  @JsonProperty(JSON_PROPERTY_COUNTRY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setCountry(String country) {
    this.country = country;
  }

  /**
   * The three-character ISO currency code of transfer. For example, **USD** or **EUR**.
   *
   * @param currency
   * @return the current {@code TransferRoute} instance, allowing for method chaining
   */
  public TransferRoute currency(String currency) {
    this.currency = currency;
    return this;
  }

  /**
   * The three-character ISO currency code of transfer. For example, **USD** or **EUR**.
   * @return currency
   */
  @ApiModelProperty(value = "The three-character ISO currency code of transfer. For example, **USD** or **EUR**.")
  @JsonProperty(JSON_PROPERTY_CURRENCY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getCurrency() {
    return currency;
  }

  /**
   * The three-character ISO currency code of transfer. For example, **USD** or **EUR**.
   *
   * @param currency
   */ 
  @JsonProperty(JSON_PROPERTY_CURRENCY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setCurrency(String currency) {
    this.currency = currency;
  }

  /**
   * The priority for the bank transfer. This sets the speed at which the transfer is sent and the fees that you have to pay. Possible values:  * **regular**: for normal, low-value transactions.  * **fast**: a faster way to transfer funds, but the fees are higher. Recommended for high-priority, low-value transactions.  * **wire**: the fastest way to transfer funds, but this has the highest fees. Recommended for high-priority, high-value transactions.  * **instant**: for instant funds transfers in [SEPA countries](https://www.ecb.europa.eu/paym/integration/retail/sepa/html/index.en.html).  * **crossBorder**: for high-value transfers to a recipient in a different country.  * **internal**: for transfers to an Adyen-issued business bank account (by bank account number/IBAN).
   *
   * @param priority
   * @return the current {@code TransferRoute} instance, allowing for method chaining
   */
  public TransferRoute priority(PriorityEnum priority) {
    this.priority = priority;
    return this;
  }

  /**
   * The priority for the bank transfer. This sets the speed at which the transfer is sent and the fees that you have to pay. Possible values:  * **regular**: for normal, low-value transactions.  * **fast**: a faster way to transfer funds, but the fees are higher. Recommended for high-priority, low-value transactions.  * **wire**: the fastest way to transfer funds, but this has the highest fees. Recommended for high-priority, high-value transactions.  * **instant**: for instant funds transfers in [SEPA countries](https://www.ecb.europa.eu/paym/integration/retail/sepa/html/index.en.html).  * **crossBorder**: for high-value transfers to a recipient in a different country.  * **internal**: for transfers to an Adyen-issued business bank account (by bank account number/IBAN).
   * @return priority
   */
  @ApiModelProperty(value = "The priority for the bank transfer. This sets the speed at which the transfer is sent and the fees that you have to pay. Possible values:  * **regular**: for normal, low-value transactions.  * **fast**: a faster way to transfer funds, but the fees are higher. Recommended for high-priority, low-value transactions.  * **wire**: the fastest way to transfer funds, but this has the highest fees. Recommended for high-priority, high-value transactions.  * **instant**: for instant funds transfers in [SEPA countries](https://www.ecb.europa.eu/paym/integration/retail/sepa/html/index.en.html).  * **crossBorder**: for high-value transfers to a recipient in a different country.  * **internal**: for transfers to an Adyen-issued business bank account (by bank account number/IBAN).")
  @JsonProperty(JSON_PROPERTY_PRIORITY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public PriorityEnum getPriority() {
    return priority;
  }

  /**
   * The priority for the bank transfer. This sets the speed at which the transfer is sent and the fees that you have to pay. Possible values:  * **regular**: for normal, low-value transactions.  * **fast**: a faster way to transfer funds, but the fees are higher. Recommended for high-priority, low-value transactions.  * **wire**: the fastest way to transfer funds, but this has the highest fees. Recommended for high-priority, high-value transactions.  * **instant**: for instant funds transfers in [SEPA countries](https://www.ecb.europa.eu/paym/integration/retail/sepa/html/index.en.html).  * **crossBorder**: for high-value transfers to a recipient in a different country.  * **internal**: for transfers to an Adyen-issued business bank account (by bank account number/IBAN).
   *
   * @param priority
   */ 
  @JsonProperty(JSON_PROPERTY_PRIORITY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setPriority(PriorityEnum priority) {
    this.priority = priority;
  }

  /**
   * A set of rules defined by clearing houses and banking partners. Your transfer request must adhere to these rules to ensure successful initiation of transfer. Based on the priority, one or more requirements may be returned. Each requirement is defined with a &#x60;type&#x60; and &#x60;description&#x60;.
   *
   * @param requirements
   * @return the current {@code TransferRoute} instance, allowing for method chaining
   */
  public TransferRoute requirements(List<TransferRouteRequirementsInner> requirements) {
    this.requirements = requirements;
    return this;
  }

  public TransferRoute addRequirementsItem(TransferRouteRequirementsInner requirementsItem) {
    if (this.requirements == null) {
      this.requirements = new ArrayList<>();
    }
    this.requirements.add(requirementsItem);
    return this;
  }

  /**
   * A set of rules defined by clearing houses and banking partners. Your transfer request must adhere to these rules to ensure successful initiation of transfer. Based on the priority, one or more requirements may be returned. Each requirement is defined with a &#x60;type&#x60; and &#x60;description&#x60;.
   * @return requirements
   */
  @ApiModelProperty(value = "A set of rules defined by clearing houses and banking partners. Your transfer request must adhere to these rules to ensure successful initiation of transfer. Based on the priority, one or more requirements may be returned. Each requirement is defined with a `type` and `description`.")
  @JsonProperty(JSON_PROPERTY_REQUIREMENTS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public List<TransferRouteRequirementsInner> getRequirements() {
    return requirements;
  }

  /**
   * A set of rules defined by clearing houses and banking partners. Your transfer request must adhere to these rules to ensure successful initiation of transfer. Based on the priority, one or more requirements may be returned. Each requirement is defined with a &#x60;type&#x60; and &#x60;description&#x60;.
   *
   * @param requirements
   */ 
  @JsonProperty(JSON_PROPERTY_REQUIREMENTS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setRequirements(List<TransferRouteRequirementsInner> requirements) {
    this.requirements = requirements;
  }

  /**
   * Return true if this TransferRoute object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    TransferRoute transferRoute = (TransferRoute) o;
    return Objects.equals(this.category, transferRoute.category) &&
        Objects.equals(this.country, transferRoute.country) &&
        Objects.equals(this.currency, transferRoute.currency) &&
        Objects.equals(this.priority, transferRoute.priority) &&
        Objects.equals(this.requirements, transferRoute.requirements);
  }

  @Override
  public int hashCode() {
    return Objects.hash(category, country, currency, priority, requirements);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class TransferRoute {\n");
    sb.append("    category: ").append(toIndentedString(category)).append("\n");
    sb.append("    country: ").append(toIndentedString(country)).append("\n");
    sb.append("    currency: ").append(toIndentedString(currency)).append("\n");
    sb.append("    priority: ").append(toIndentedString(priority)).append("\n");
    sb.append("    requirements: ").append(toIndentedString(requirements)).append("\n");
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
   * Create an instance of TransferRoute given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of TransferRoute
   * @throws JsonProcessingException if the JSON string is invalid with respect to TransferRoute
   */
  public static TransferRoute fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, TransferRoute.class);
  }
/**
  * Convert an instance of TransferRoute to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}
