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
import com.adyen.model.balanceplatform.Device;
import com.adyen.model.balanceplatform.Link;
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
 * SearchRegisteredDevicesResponse
 */
@JsonPropertyOrder({
  SearchRegisteredDevicesResponse.JSON_PROPERTY_DATA,
  SearchRegisteredDevicesResponse.JSON_PROPERTY_ITEMS_TOTAL,
  SearchRegisteredDevicesResponse.JSON_PROPERTY_LINK,
  SearchRegisteredDevicesResponse.JSON_PROPERTY_PAGES_TOTAL
})

public class SearchRegisteredDevicesResponse {
  public static final String JSON_PROPERTY_DATA = "data";
  private List<Device> data = null;

  public static final String JSON_PROPERTY_ITEMS_TOTAL = "itemsTotal";
  private Integer itemsTotal;

  public static final String JSON_PROPERTY_LINK = "link";
  private Link link;

  public static final String JSON_PROPERTY_PAGES_TOTAL = "pagesTotal";
  private Integer pagesTotal;

  public SearchRegisteredDevicesResponse() { 
  }

  /**
   * Contains a list of registered SCA devices and their corresponding details.
   *
   * @param data
   * @return the current {@code SearchRegisteredDevicesResponse} instance, allowing for method chaining
   */
  public SearchRegisteredDevicesResponse data(List<Device> data) {
    this.data = data;
    return this;
  }

  public SearchRegisteredDevicesResponse addDataItem(Device dataItem) {
    if (this.data == null) {
      this.data = new ArrayList<>();
    }
    this.data.add(dataItem);
    return this;
  }

  /**
   * Contains a list of registered SCA devices and their corresponding details.
   * @return data
   */
  @ApiModelProperty(value = "Contains a list of registered SCA devices and their corresponding details.")
  @JsonProperty(JSON_PROPERTY_DATA)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public List<Device> getData() {
    return data;
  }

  /**
   * Contains a list of registered SCA devices and their corresponding details.
   *
   * @param data
   */ 
  @JsonProperty(JSON_PROPERTY_DATA)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setData(List<Device> data) {
    this.data = data;
  }

  /**
   * The total amount of registered SCA devices that match the query parameters.
   *
   * @param itemsTotal
   * @return the current {@code SearchRegisteredDevicesResponse} instance, allowing for method chaining
   */
  public SearchRegisteredDevicesResponse itemsTotal(Integer itemsTotal) {
    this.itemsTotal = itemsTotal;
    return this;
  }

  /**
   * The total amount of registered SCA devices that match the query parameters.
   * @return itemsTotal
   */
  @ApiModelProperty(value = "The total amount of registered SCA devices that match the query parameters.")
  @JsonProperty(JSON_PROPERTY_ITEMS_TOTAL)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public Integer getItemsTotal() {
    return itemsTotal;
  }

  /**
   * The total amount of registered SCA devices that match the query parameters.
   *
   * @param itemsTotal
   */ 
  @JsonProperty(JSON_PROPERTY_ITEMS_TOTAL)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setItemsTotal(Integer itemsTotal) {
    this.itemsTotal = itemsTotal;
  }

  /**
   * link
   *
   * @param link
   * @return the current {@code SearchRegisteredDevicesResponse} instance, allowing for method chaining
   */
  public SearchRegisteredDevicesResponse link(Link link) {
    this.link = link;
    return this;
  }

  /**
   * link
   * @return link
   */
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_LINK)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public Link getLink() {
    return link;
  }

  /**
   * link
   *
   * @param link
   */ 
  @JsonProperty(JSON_PROPERTY_LINK)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setLink(Link link) {
    this.link = link;
  }

  /**
   * The total amount of list pages.
   *
   * @param pagesTotal
   * @return the current {@code SearchRegisteredDevicesResponse} instance, allowing for method chaining
   */
  public SearchRegisteredDevicesResponse pagesTotal(Integer pagesTotal) {
    this.pagesTotal = pagesTotal;
    return this;
  }

  /**
   * The total amount of list pages.
   * @return pagesTotal
   */
  @ApiModelProperty(value = "The total amount of list pages.")
  @JsonProperty(JSON_PROPERTY_PAGES_TOTAL)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public Integer getPagesTotal() {
    return pagesTotal;
  }

  /**
   * The total amount of list pages.
   *
   * @param pagesTotal
   */ 
  @JsonProperty(JSON_PROPERTY_PAGES_TOTAL)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setPagesTotal(Integer pagesTotal) {
    this.pagesTotal = pagesTotal;
  }

  /**
   * Return true if this SearchRegisteredDevicesResponse object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    SearchRegisteredDevicesResponse searchRegisteredDevicesResponse = (SearchRegisteredDevicesResponse) o;
    return Objects.equals(this.data, searchRegisteredDevicesResponse.data) &&
        Objects.equals(this.itemsTotal, searchRegisteredDevicesResponse.itemsTotal) &&
        Objects.equals(this.link, searchRegisteredDevicesResponse.link) &&
        Objects.equals(this.pagesTotal, searchRegisteredDevicesResponse.pagesTotal);
  }

  @Override
  public int hashCode() {
    return Objects.hash(data, itemsTotal, link, pagesTotal);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class SearchRegisteredDevicesResponse {\n");
    sb.append("    data: ").append(toIndentedString(data)).append("\n");
    sb.append("    itemsTotal: ").append(toIndentedString(itemsTotal)).append("\n");
    sb.append("    link: ").append(toIndentedString(link)).append("\n");
    sb.append("    pagesTotal: ").append(toIndentedString(pagesTotal)).append("\n");
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
   * Create an instance of SearchRegisteredDevicesResponse given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of SearchRegisteredDevicesResponse
   * @throws JsonProcessingException if the JSON string is invalid with respect to SearchRegisteredDevicesResponse
   */
  public static SearchRegisteredDevicesResponse fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, SearchRegisteredDevicesResponse.class);
  }
/**
  * Convert an instance of SearchRegisteredDevicesResponse to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}
