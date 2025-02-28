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
 * PriorityRestriction
 */
@JsonPropertyOrder({
  PriorityRestriction.JSON_PROPERTY_OPERATION,
  PriorityRestriction.JSON_PROPERTY_VALUE
})

public class PriorityRestriction {
  public static final String JSON_PROPERTY_OPERATION = "operation";
  private String operation;

  /**
   * Gets or Sets value
   */
  public enum ValueEnum {
    CROSSBORDER("crossBorder"),
    
    FAST("fast"),
    
    INSTANT("instant"),
    
    INTRABANK("intraBank"),
    
    REGULAR("regular");

    private String value;

    ValueEnum(String value) {
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
    public static ValueEnum fromValue(String value) {
      for (ValueEnum b : ValueEnum.values()) {
        if (b.value.equals(value)) {
          return b;
        }
      }
      throw new IllegalArgumentException("Unexpected value '" + value + "'");
    }
  }

  public static final String JSON_PROPERTY_VALUE = "value";
  private List<ValueEnum> value = null;

  public PriorityRestriction() { 
  }

  /**
   * Defines how the condition must be evaluated.
   *
   * @param operation
   * @return the current {@code PriorityRestriction} instance, allowing for method chaining
   */
  public PriorityRestriction operation(String operation) {
    this.operation = operation;
    return this;
  }

  /**
   * Defines how the condition must be evaluated.
   * @return operation
   */
  @ApiModelProperty(required = true, value = "Defines how the condition must be evaluated.")
  @JsonProperty(JSON_PROPERTY_OPERATION)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getOperation() {
    return operation;
  }

  /**
   * Defines how the condition must be evaluated.
   *
   * @param operation
   */ 
  @JsonProperty(JSON_PROPERTY_OPERATION)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setOperation(String operation) {
    this.operation = operation;
  }

  /**
   * value
   *
   * @param value
   * @return the current {@code PriorityRestriction} instance, allowing for method chaining
   */
  public PriorityRestriction value(List<ValueEnum> value) {
    this.value = value;
    return this;
  }

  public PriorityRestriction addValueItem(ValueEnum valueItem) {
    if (this.value == null) {
      this.value = new ArrayList<>();
    }
    this.value.add(valueItem);
    return this;
  }

  /**
   * value
   * @return value
   */
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_VALUE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public List<ValueEnum> getValue() {
    return value;
  }

  /**
   * value
   *
   * @param value
   */ 
  @JsonProperty(JSON_PROPERTY_VALUE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setValue(List<ValueEnum> value) {
    this.value = value;
  }

  /**
   * Return true if this PriorityRestriction object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    PriorityRestriction priorityRestriction = (PriorityRestriction) o;
    return Objects.equals(this.operation, priorityRestriction.operation) &&
        Objects.equals(this.value, priorityRestriction.value);
  }

  @Override
  public int hashCode() {
    return Objects.hash(operation, value);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class PriorityRestriction {\n");
    sb.append("    operation: ").append(toIndentedString(operation)).append("\n");
    sb.append("    value: ").append(toIndentedString(value)).append("\n");
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
   * Create an instance of PriorityRestriction given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of PriorityRestriction
   * @throws JsonProcessingException if the JSON string is invalid with respect to PriorityRestriction
   */
  public static PriorityRestriction fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, PriorityRestriction.class);
  }
/**
  * Convert an instance of PriorityRestriction to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}
