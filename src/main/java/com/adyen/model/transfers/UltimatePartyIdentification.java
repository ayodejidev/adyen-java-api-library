/*
 * Transfers API
 *
 * The version of the OpenAPI document: 4
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.adyen.model.transfers;

import java.util.Objects;
import java.util.Arrays;
import java.util.Map;
import java.util.HashMap;
import com.adyen.model.transfers.Address;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.annotation.JsonValue;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import java.time.LocalDate;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.core.JsonProcessingException;


/**
 * UltimatePartyIdentification
 */
@JsonPropertyOrder({
  UltimatePartyIdentification.JSON_PROPERTY_ADDRESS,
  UltimatePartyIdentification.JSON_PROPERTY_DATE_OF_BIRTH,
  UltimatePartyIdentification.JSON_PROPERTY_FIRST_NAME,
  UltimatePartyIdentification.JSON_PROPERTY_FULL_NAME,
  UltimatePartyIdentification.JSON_PROPERTY_LAST_NAME,
  UltimatePartyIdentification.JSON_PROPERTY_REFERENCE,
  UltimatePartyIdentification.JSON_PROPERTY_TYPE
})

public class UltimatePartyIdentification {
  public static final String JSON_PROPERTY_ADDRESS = "address";
  private Address address;

  public static final String JSON_PROPERTY_DATE_OF_BIRTH = "dateOfBirth";
  private LocalDate dateOfBirth;

  public static final String JSON_PROPERTY_FIRST_NAME = "firstName";
  private String firstName;

  public static final String JSON_PROPERTY_FULL_NAME = "fullName";
  private String fullName;

  public static final String JSON_PROPERTY_LAST_NAME = "lastName";
  private String lastName;

  public static final String JSON_PROPERTY_REFERENCE = "reference";
  private String reference;

  /**
   * The type of entity that owns the bank account or card.  Possible values: **individual**, **organization**, or **unknown**.  Required when &#x60;category&#x60; is **card**. In this case, the value must be **individual**.
   */
  public enum TypeEnum {
    INDIVIDUAL("individual"),
    
    ORGANIZATION("organization"),
    
    UNKNOWN("unknown");

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

  public UltimatePartyIdentification() { 
  }

  /**
   * address
   *
   * @param address
   * @return the current {@code UltimatePartyIdentification} instance, allowing for method chaining
   */
  public UltimatePartyIdentification address(Address address) {
    this.address = address;
    return this;
  }

  /**
   * address
   * @return address
   */
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_ADDRESS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public Address getAddress() {
    return address;
  }

  /**
   * address
   *
   * @param address
   */ 
  @JsonProperty(JSON_PROPERTY_ADDRESS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setAddress(Address address) {
    this.address = address;
  }

  /**
   * The date of birth of the individual in [ISO-8601](https://www.w3.org/TR/NOTE-datetime) format. For example, **YYYY-MM-DD**.  Allowed only when &#x60;type&#x60; is **individual**.
   *
   * @param dateOfBirth
   * @return the current {@code UltimatePartyIdentification} instance, allowing for method chaining
   */
  public UltimatePartyIdentification dateOfBirth(LocalDate dateOfBirth) {
    this.dateOfBirth = dateOfBirth;
    return this;
  }

  /**
   * The date of birth of the individual in [ISO-8601](https://www.w3.org/TR/NOTE-datetime) format. For example, **YYYY-MM-DD**.  Allowed only when &#x60;type&#x60; is **individual**.
   * @return dateOfBirth
   */
  @ApiModelProperty(value = "The date of birth of the individual in [ISO-8601](https://www.w3.org/TR/NOTE-datetime) format. For example, **YYYY-MM-DD**.  Allowed only when `type` is **individual**.")
  @JsonProperty(JSON_PROPERTY_DATE_OF_BIRTH)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public LocalDate getDateOfBirth() {
    return dateOfBirth;
  }

  /**
   * The date of birth of the individual in [ISO-8601](https://www.w3.org/TR/NOTE-datetime) format. For example, **YYYY-MM-DD**.  Allowed only when &#x60;type&#x60; is **individual**.
   *
   * @param dateOfBirth
   */ 
  @JsonProperty(JSON_PROPERTY_DATE_OF_BIRTH)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setDateOfBirth(LocalDate dateOfBirth) {
    this.dateOfBirth = dateOfBirth;
  }

  /**
   * The first name of the individual.  Supported characters: [a-z] [A-Z] - . / — and space.  This parameter is: - Allowed only when &#x60;type&#x60; is **individual**. - Required when &#x60;category&#x60; is **card**.
   *
   * @param firstName
   * @return the current {@code UltimatePartyIdentification} instance, allowing for method chaining
   */
  public UltimatePartyIdentification firstName(String firstName) {
    this.firstName = firstName;
    return this;
  }

  /**
   * The first name of the individual.  Supported characters: [a-z] [A-Z] - . / — and space.  This parameter is: - Allowed only when &#x60;type&#x60; is **individual**. - Required when &#x60;category&#x60; is **card**.
   * @return firstName
   */
  @ApiModelProperty(value = "The first name of the individual.  Supported characters: [a-z] [A-Z] - . / — and space.  This parameter is: - Allowed only when `type` is **individual**. - Required when `category` is **card**.")
  @JsonProperty(JSON_PROPERTY_FIRST_NAME)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getFirstName() {
    return firstName;
  }

  /**
   * The first name of the individual.  Supported characters: [a-z] [A-Z] - . / — and space.  This parameter is: - Allowed only when &#x60;type&#x60; is **individual**. - Required when &#x60;category&#x60; is **card**.
   *
   * @param firstName
   */ 
  @JsonProperty(JSON_PROPERTY_FIRST_NAME)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setFirstName(String firstName) {
    this.firstName = firstName;
  }

  /**
   * The full name of the entity that owns the bank account or card.  Supported characters: [a-z] [A-Z] [0-9] , . ; : - — / \\ + &amp; ! ? @ ( ) \&quot; &#39; and space.  Required when &#x60;category&#x60; is **bank**.
   *
   * @param fullName
   * @return the current {@code UltimatePartyIdentification} instance, allowing for method chaining
   */
  public UltimatePartyIdentification fullName(String fullName) {
    this.fullName = fullName;
    return this;
  }

  /**
   * The full name of the entity that owns the bank account or card.  Supported characters: [a-z] [A-Z] [0-9] , . ; : - — / \\ + &amp; ! ? @ ( ) \&quot; &#39; and space.  Required when &#x60;category&#x60; is **bank**.
   * @return fullName
   */
  @ApiModelProperty(value = "The full name of the entity that owns the bank account or card.  Supported characters: [a-z] [A-Z] [0-9] , . ; : - — / \\ + & ! ? @ ( ) \" ' and space.  Required when `category` is **bank**.")
  @JsonProperty(JSON_PROPERTY_FULL_NAME)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getFullName() {
    return fullName;
  }

  /**
   * The full name of the entity that owns the bank account or card.  Supported characters: [a-z] [A-Z] [0-9] , . ; : - — / \\ + &amp; ! ? @ ( ) \&quot; &#39; and space.  Required when &#x60;category&#x60; is **bank**.
   *
   * @param fullName
   */ 
  @JsonProperty(JSON_PROPERTY_FULL_NAME)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setFullName(String fullName) {
    this.fullName = fullName;
  }

  /**
   * The last name of the individual.  Supported characters: [a-z] [A-Z] - . / — and space.  This parameter is: - Allowed only when &#x60;type&#x60; is **individual**. - Required when &#x60;category&#x60; is **card**.
   *
   * @param lastName
   * @return the current {@code UltimatePartyIdentification} instance, allowing for method chaining
   */
  public UltimatePartyIdentification lastName(String lastName) {
    this.lastName = lastName;
    return this;
  }

  /**
   * The last name of the individual.  Supported characters: [a-z] [A-Z] - . / — and space.  This parameter is: - Allowed only when &#x60;type&#x60; is **individual**. - Required when &#x60;category&#x60; is **card**.
   * @return lastName
   */
  @ApiModelProperty(value = "The last name of the individual.  Supported characters: [a-z] [A-Z] - . / — and space.  This parameter is: - Allowed only when `type` is **individual**. - Required when `category` is **card**.")
  @JsonProperty(JSON_PROPERTY_LAST_NAME)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getLastName() {
    return lastName;
  }

  /**
   * The last name of the individual.  Supported characters: [a-z] [A-Z] - . / — and space.  This parameter is: - Allowed only when &#x60;type&#x60; is **individual**. - Required when &#x60;category&#x60; is **card**.
   *
   * @param lastName
   */ 
  @JsonProperty(JSON_PROPERTY_LAST_NAME)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setLastName(String lastName) {
    this.lastName = lastName;
  }

  /**
   * A unique reference to identify the party or counterparty involved in the transfer. For example, your client&#39;s unique wallet or payee ID.  Required when you include &#x60;cardIdentification.storedPaymentMethodId&#x60;.
   *
   * @param reference
   * @return the current {@code UltimatePartyIdentification} instance, allowing for method chaining
   */
  public UltimatePartyIdentification reference(String reference) {
    this.reference = reference;
    return this;
  }

  /**
   * A unique reference to identify the party or counterparty involved in the transfer. For example, your client&#39;s unique wallet or payee ID.  Required when you include &#x60;cardIdentification.storedPaymentMethodId&#x60;.
   * @return reference
   */
  @ApiModelProperty(value = "A unique reference to identify the party or counterparty involved in the transfer. For example, your client's unique wallet or payee ID.  Required when you include `cardIdentification.storedPaymentMethodId`.")
  @JsonProperty(JSON_PROPERTY_REFERENCE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getReference() {
    return reference;
  }

  /**
   * A unique reference to identify the party or counterparty involved in the transfer. For example, your client&#39;s unique wallet or payee ID.  Required when you include &#x60;cardIdentification.storedPaymentMethodId&#x60;.
   *
   * @param reference
   */ 
  @JsonProperty(JSON_PROPERTY_REFERENCE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setReference(String reference) {
    this.reference = reference;
  }

  /**
   * The type of entity that owns the bank account or card.  Possible values: **individual**, **organization**, or **unknown**.  Required when &#x60;category&#x60; is **card**. In this case, the value must be **individual**.
   *
   * @param type
   * @return the current {@code UltimatePartyIdentification} instance, allowing for method chaining
   */
  public UltimatePartyIdentification type(TypeEnum type) {
    this.type = type;
    return this;
  }

  /**
   * The type of entity that owns the bank account or card.  Possible values: **individual**, **organization**, or **unknown**.  Required when &#x60;category&#x60; is **card**. In this case, the value must be **individual**.
   * @return type
   */
  @ApiModelProperty(value = "The type of entity that owns the bank account or card.  Possible values: **individual**, **organization**, or **unknown**.  Required when `category` is **card**. In this case, the value must be **individual**.")
  @JsonProperty(JSON_PROPERTY_TYPE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public TypeEnum getType() {
    return type;
  }

  /**
   * The type of entity that owns the bank account or card.  Possible values: **individual**, **organization**, or **unknown**.  Required when &#x60;category&#x60; is **card**. In this case, the value must be **individual**.
   *
   * @param type
   */ 
  @JsonProperty(JSON_PROPERTY_TYPE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setType(TypeEnum type) {
    this.type = type;
  }

  /**
   * Return true if this UltimatePartyIdentification object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    UltimatePartyIdentification ultimatePartyIdentification = (UltimatePartyIdentification) o;
    return Objects.equals(this.address, ultimatePartyIdentification.address) &&
        Objects.equals(this.dateOfBirth, ultimatePartyIdentification.dateOfBirth) &&
        Objects.equals(this.firstName, ultimatePartyIdentification.firstName) &&
        Objects.equals(this.fullName, ultimatePartyIdentification.fullName) &&
        Objects.equals(this.lastName, ultimatePartyIdentification.lastName) &&
        Objects.equals(this.reference, ultimatePartyIdentification.reference) &&
        Objects.equals(this.type, ultimatePartyIdentification.type);
  }

  @Override
  public int hashCode() {
    return Objects.hash(address, dateOfBirth, firstName, fullName, lastName, reference, type);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class UltimatePartyIdentification {\n");
    sb.append("    address: ").append(toIndentedString(address)).append("\n");
    sb.append("    dateOfBirth: ").append(toIndentedString(dateOfBirth)).append("\n");
    sb.append("    firstName: ").append(toIndentedString(firstName)).append("\n");
    sb.append("    fullName: ").append(toIndentedString(fullName)).append("\n");
    sb.append("    lastName: ").append(toIndentedString(lastName)).append("\n");
    sb.append("    reference: ").append(toIndentedString(reference)).append("\n");
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
   * Create an instance of UltimatePartyIdentification given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of UltimatePartyIdentification
   * @throws JsonProcessingException if the JSON string is invalid with respect to UltimatePartyIdentification
   */
  public static UltimatePartyIdentification fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, UltimatePartyIdentification.class);
  }
/**
  * Convert an instance of UltimatePartyIdentification to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}
