/*
 * Legal Entity Management API
 *
 * The version of the OpenAPI document: 3
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.adyen.model.legalentitymanagement;

import java.util.Objects;
import java.util.Arrays;
import java.util.Map;
import java.util.HashMap;
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
 * UKLocalAccountIdentification
 */
@JsonPropertyOrder({
  UKLocalAccountIdentification.JSON_PROPERTY_ACCOUNT_NUMBER,
  UKLocalAccountIdentification.JSON_PROPERTY_FORM_FACTOR,
  UKLocalAccountIdentification.JSON_PROPERTY_SORT_CODE,
  UKLocalAccountIdentification.JSON_PROPERTY_TYPE
})

public class UKLocalAccountIdentification {
  public static final String JSON_PROPERTY_ACCOUNT_NUMBER = "accountNumber";
  private String accountNumber;

  public static final String JSON_PROPERTY_FORM_FACTOR = "formFactor";
  private String formFactor;

  public static final String JSON_PROPERTY_SORT_CODE = "sortCode";
  private String sortCode;

  /**
   * **ukLocal**
   */
  public enum TypeEnum {
    UKLOCAL("ukLocal");

    private String value;

    TypeEnum(String value) {
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
    public static TypeEnum fromValue(String value) {
      for (TypeEnum b : TypeEnum.values()) {
        if (b.value.equals(value)) {
          return b;
        }
      }
      throw new IllegalArgumentException("Unexpected value '" + value + "'");
    }
  }

  public static final String JSON_PROPERTY_TYPE = "type";
  private TypeEnum type;

  public UKLocalAccountIdentification() { 
  }

  public UKLocalAccountIdentification accountNumber(String accountNumber) {
    this.accountNumber = accountNumber;
    return this;
  }

   /**
   * The 8-digit bank account number, without separators or whitespace.
   * @return accountNumber
  **/
  @ApiModelProperty(required = true, value = "The 8-digit bank account number, without separators or whitespace.")
  @JsonProperty(JSON_PROPERTY_ACCOUNT_NUMBER)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getAccountNumber() {
    return accountNumber;
  }


 /**
  * The 8-digit bank account number, without separators or whitespace.
  *
  * @param accountNumber
  */ 
  @JsonProperty(JSON_PROPERTY_ACCOUNT_NUMBER)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setAccountNumber(String accountNumber) {
    this.accountNumber = accountNumber;
  }


  public UKLocalAccountIdentification formFactor(String formFactor) {
    this.formFactor = formFactor;
    return this;
  }

   /**
   * Business accounts with a &#x60;formFactor&#x60; value of **physical** are business accounts issued under the central bank of that country. The default value is **physical** for NL, US, and UK business accounts.   Adyen creates a local IBAN for business accounts when the &#x60;formFactor&#x60; value is set to **virtual**. The local IBANs that are supported are for DE and FR, which reference a physical NL account, with funds being routed through the central bank of NL.
   * @return formFactor
  **/
  @ApiModelProperty(value = "Business accounts with a `formFactor` value of **physical** are business accounts issued under the central bank of that country. The default value is **physical** for NL, US, and UK business accounts.   Adyen creates a local IBAN for business accounts when the `formFactor` value is set to **virtual**. The local IBANs that are supported are for DE and FR, which reference a physical NL account, with funds being routed through the central bank of NL.")
  @JsonProperty(JSON_PROPERTY_FORM_FACTOR)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getFormFactor() {
    return formFactor;
  }


 /**
  * Business accounts with a &#x60;formFactor&#x60; value of **physical** are business accounts issued under the central bank of that country. The default value is **physical** for NL, US, and UK business accounts.   Adyen creates a local IBAN for business accounts when the &#x60;formFactor&#x60; value is set to **virtual**. The local IBANs that are supported are for DE and FR, which reference a physical NL account, with funds being routed through the central bank of NL.
  *
  * @param formFactor
  */ 
  @JsonProperty(JSON_PROPERTY_FORM_FACTOR)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setFormFactor(String formFactor) {
    this.formFactor = formFactor;
  }


  public UKLocalAccountIdentification sortCode(String sortCode) {
    this.sortCode = sortCode;
    return this;
  }

   /**
   * The 6-digit [sort code](https://en.wikipedia.org/wiki/Sort_code), without separators or whitespace.
   * @return sortCode
  **/
  @ApiModelProperty(required = true, value = "The 6-digit [sort code](https://en.wikipedia.org/wiki/Sort_code), without separators or whitespace.")
  @JsonProperty(JSON_PROPERTY_SORT_CODE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getSortCode() {
    return sortCode;
  }


 /**
  * The 6-digit [sort code](https://en.wikipedia.org/wiki/Sort_code), without separators or whitespace.
  *
  * @param sortCode
  */ 
  @JsonProperty(JSON_PROPERTY_SORT_CODE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setSortCode(String sortCode) {
    this.sortCode = sortCode;
  }


  public UKLocalAccountIdentification type(TypeEnum type) {
    this.type = type;
    return this;
  }

   /**
   * **ukLocal**
   * @return type
  **/
  @ApiModelProperty(required = true, value = "**ukLocal**")
  @JsonProperty(JSON_PROPERTY_TYPE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public TypeEnum getType() {
    return type;
  }


 /**
  * **ukLocal**
  *
  * @param type
  */ 
  @JsonProperty(JSON_PROPERTY_TYPE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setType(TypeEnum type) {
    this.type = type;
  }


  /**
   * Return true if this UKLocalAccountIdentification object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    UKLocalAccountIdentification ukLocalAccountIdentification = (UKLocalAccountIdentification) o;
    return Objects.equals(this.accountNumber, ukLocalAccountIdentification.accountNumber) &&
        Objects.equals(this.formFactor, ukLocalAccountIdentification.formFactor) &&
        Objects.equals(this.sortCode, ukLocalAccountIdentification.sortCode) &&
        Objects.equals(this.type, ukLocalAccountIdentification.type);
  }

  @Override
  public int hashCode() {
    return Objects.hash(accountNumber, formFactor, sortCode, type);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class UKLocalAccountIdentification {\n");
    sb.append("    accountNumber: ").append(toIndentedString(accountNumber)).append("\n");
    sb.append("    formFactor: ").append(toIndentedString(formFactor)).append("\n");
    sb.append("    sortCode: ").append(toIndentedString(sortCode)).append("\n");
    sb.append("    type: ").append(toIndentedString(type)).append("\n");
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
   * Create an instance of UKLocalAccountIdentification given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of UKLocalAccountIdentification
   * @throws JsonProcessingException if the JSON string is invalid with respect to UKLocalAccountIdentification
   */
  public static UKLocalAccountIdentification fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, UKLocalAccountIdentification.class);
  }
/**
  * Convert an instance of UKLocalAccountIdentification to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}

