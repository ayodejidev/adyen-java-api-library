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
import com.adyen.model.terminal.DisplayOutput;
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
 * It conveys the data to display and the way to process the display. It contains the complete content to display. It might contain an operation (the DisplayOutput element) per Display Device type. Content of the Display Request message.
 */
@ApiModel(description = "It conveys the data to display and the way to process the display. It contains the complete content to display. It might contain an operation (the DisplayOutput element) per Display Device type. Content of the Display Request message.")
@JsonPropertyOrder({
  DisplayRequest.JSON_PROPERTY_DISPLAY_OUTPUT
})

public class DisplayRequest {
  public static final String JSON_PROPERTY_DISPLAY_OUTPUT = "DisplayOutput";
  private List<DisplayOutput> displayOutput = new ArrayList<>();

  public DisplayRequest() { 
  }

  public DisplayRequest displayOutput(List<DisplayOutput> displayOutput) {
    this.displayOutput = displayOutput;
    return this;
  }

  public DisplayRequest addDisplayOutputItem(DisplayOutput displayOutputItem) {
    this.displayOutput.add(displayOutputItem);
    return this;
  }

   /**
   * Get displayOutput
   * @return displayOutput
  **/
  @ApiModelProperty(required = true, value = "")
  @JsonProperty(JSON_PROPERTY_DISPLAY_OUTPUT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public List<DisplayOutput> getDisplayOutput() {
    return displayOutput;
  }


 /**
  * displayOutput
  *
  * @param displayOutput
  */ 
  @JsonProperty(JSON_PROPERTY_DISPLAY_OUTPUT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setDisplayOutput(List<DisplayOutput> displayOutput) {
    this.displayOutput = displayOutput;
  }


  /**
   * Return true if this DisplayRequest object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    DisplayRequest displayRequest = (DisplayRequest) o;
    return Objects.equals(this.displayOutput, displayRequest.displayOutput);
  }

  @Override
  public int hashCode() {
    return Objects.hash(displayOutput);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class DisplayRequest {\n");
    sb.append("    displayOutput: ").append(toIndentedString(displayOutput)).append("\n");
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
   * Create an instance of DisplayRequest given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of DisplayRequest
   * @throws JsonProcessingException if the JSON string is invalid with respect to DisplayRequest
   */
  public static DisplayRequest fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, DisplayRequest.class);
  }
/**
  * Convert an instance of DisplayRequest to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}
