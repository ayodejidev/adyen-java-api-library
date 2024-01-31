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
 * DayOfWeekRestriction
 */
@JsonPropertyOrder({
  DayOfWeekRestriction.JSON_PROPERTY_OPERATION,
  DayOfWeekRestriction.JSON_PROPERTY_VALUE
})

public class DayOfWeekRestriction {
  public static final String JSON_PROPERTY_OPERATION = "operation";
  private String operation;

  /**
   * Gets or Sets value
   */
  public enum ValueEnum {
    FRIDAY("friday"),
    
    MONDAY("monday"),
    
    SATURDAY("saturday"),
    
    SUNDAY("sunday"),
    
    THURSDAY("thursday"),
    
    TUESDAY("tuesday"),
    
    WEDNESDAY("wednesday");

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

  public DayOfWeekRestriction() { 
  }

  public DayOfWeekRestriction operation(String operation) {
    this.operation = operation;
    return this;
  }

   /**
   * Defines how the condition must be evaluated.
   * @return operation
  **/
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


  public DayOfWeekRestriction value(List<ValueEnum> value) {
    this.value = value;
    return this;
  }

  public DayOfWeekRestriction addValueItem(ValueEnum valueItem) {
    if (this.value == null) {
      this.value = new ArrayList<>();
    }
    this.value.add(valueItem);
    return this;
  }

   /**
   * List of days of the week.  Possible values: **monday**, **tuesday**, **wednesday**, **thursday**, **friday**, **saturday**, **sunday**.  
   * @return value
  **/
  @ApiModelProperty(value = "List of days of the week.  Possible values: **monday**, **tuesday**, **wednesday**, **thursday**, **friday**, **saturday**, **sunday**.  ")
  @JsonProperty(JSON_PROPERTY_VALUE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public List<ValueEnum> getValue() {
    return value;
  }


 /**
  * List of days of the week.  Possible values: **monday**, **tuesday**, **wednesday**, **thursday**, **friday**, **saturday**, **sunday**.  
  *
  * @param value
  */ 
  @JsonProperty(JSON_PROPERTY_VALUE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setValue(List<ValueEnum> value) {
    this.value = value;
  }


  /**
   * Return true if this DayOfWeekRestriction object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    DayOfWeekRestriction dayOfWeekRestriction = (DayOfWeekRestriction) o;
    return Objects.equals(this.operation, dayOfWeekRestriction.operation) &&
        Objects.equals(this.value, dayOfWeekRestriction.value);
  }

  @Override
  public int hashCode() {
    return Objects.hash(operation, value);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class DayOfWeekRestriction {\n");
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
   * Create an instance of DayOfWeekRestriction given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of DayOfWeekRestriction
   * @throws JsonProcessingException if the JSON string is invalid with respect to DayOfWeekRestriction
   */
  public static DayOfWeekRestriction fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, DayOfWeekRestriction.class);
  }
/**
  * Convert an instance of DayOfWeekRestriction to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}

