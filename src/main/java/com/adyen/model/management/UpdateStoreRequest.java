/*
 * Management API
 *
 * The version of the OpenAPI document: 1
 * Contact: developer-experience@adyen.com
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.adyen.model.management;

import java.util.Objects;
import java.util.Arrays;
import com.adyen.model.management.StoreSplitConfiguration;
import com.adyen.model.management.UpdatableAddress;
import com.google.gson.TypeAdapter;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.TypeAdapterFactory;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import com.adyen.model.management.JSON;

/**
 * UpdateStoreRequest
 */

public class UpdateStoreRequest {
  public static final String SERIALIZED_NAME_ADDRESS = "address";
  @SerializedName(SERIALIZED_NAME_ADDRESS)
  private UpdatableAddress address;

  public static final String SERIALIZED_NAME_BUSINESS_LINE_IDS = "businessLineIds";
  @SerializedName(SERIALIZED_NAME_BUSINESS_LINE_IDS)
  private List<String> businessLineIds = null;

  public static final String SERIALIZED_NAME_DESCRIPTION = "description";
  @SerializedName(SERIALIZED_NAME_DESCRIPTION)
  private String description;

  public static final String SERIALIZED_NAME_EXTERNAL_REFERENCE_ID = "externalReferenceId";
  @SerializedName(SERIALIZED_NAME_EXTERNAL_REFERENCE_ID)
  private String externalReferenceId;

  public static final String SERIALIZED_NAME_SPLIT_CONFIGURATION = "splitConfiguration";
  @SerializedName(SERIALIZED_NAME_SPLIT_CONFIGURATION)
  private StoreSplitConfiguration splitConfiguration;

  /**
   * The status of the store. Possible values are:  - **active**: This value is assigned automatically when a store is created.  - **inactive**: The maximum [transaction limits and number of Store-and-Forward transactions](https://docs.adyen.com/point-of-sale/determine-account-structure/configure-features#payment-features) for the store are set to 0. This blocks new transactions, but captures are still possible. - **closed**: The terminals of the store are reassigned to the merchant inventory, so they can&#39;t process payments.  You can change the status from **active** to **inactive**, and from **inactive** to **active** or **closed**.  Once **closed**, a store can&#39;t be reopened.
   */
  @JsonAdapter(StatusEnum.Adapter.class)
  public enum StatusEnum {
    ACTIVE("active"),
    
    CLOSED("closed"),
    
    INACTIVE("inactive");

    private String value;

    StatusEnum(String value) {
      this.value = value;
    }

    public String getValue() {
      return value;
    }

    @Override
    public String toString() {
      return String.valueOf(value);
    }

    public static StatusEnum fromValue(String value) {
      for (StatusEnum b : StatusEnum.values()) {
        if (b.value.equals(value)) {
          return b;
        }
      }
      throw new IllegalArgumentException("Unexpected value '" + value + "'");
    }

    public static class Adapter extends TypeAdapter<StatusEnum> {
      @Override
      public void write(final JsonWriter jsonWriter, final StatusEnum enumeration) throws IOException {
        jsonWriter.value(enumeration.getValue());
      }

      @Override
      public StatusEnum read(final JsonReader jsonReader) throws IOException {
        String value =  jsonReader.nextString();
        return StatusEnum.fromValue(value);
      }
    }
  }

  public static final String SERIALIZED_NAME_STATUS = "status";
  @SerializedName(SERIALIZED_NAME_STATUS)
  private StatusEnum status;

  public UpdateStoreRequest() { 
  }

  public UpdateStoreRequest address(UpdatableAddress address) {
    
    this.address = address;
    return this;
  }

   /**
   * Get address
   * @return address
  **/
  @ApiModelProperty(value = "")

  public UpdatableAddress getAddress() {
    return address;
  }


  public void setAddress(UpdatableAddress address) {
    this.address = address;
  }


  public UpdateStoreRequest businessLineIds(List<String> businessLineIds) {
    
    this.businessLineIds = businessLineIds;
    return this;
  }

  public UpdateStoreRequest addBusinessLineIdsItem(String businessLineIdsItem) {
    if (this.businessLineIds == null) {
      this.businessLineIds = new ArrayList<>();
    }
    this.businessLineIds.add(businessLineIdsItem);
    return this;
  }

   /**
   * The unique identifiers of the [business lines](https://docs.adyen.com/api-explorer/#/legalentity/latest/post/businesslines__resParam_id) that the store is associated with.
   * @return businessLineIds
  **/
  @ApiModelProperty(value = "The unique identifiers of the [business lines](https://docs.adyen.com/api-explorer/#/legalentity/latest/post/businesslines__resParam_id) that the store is associated with.")

  public List<String> getBusinessLineIds() {
    return businessLineIds;
  }


  public void setBusinessLineIds(List<String> businessLineIds) {
    this.businessLineIds = businessLineIds;
  }


  public UpdateStoreRequest description(String description) {
    
    this.description = description;
    return this;
  }

   /**
   * The description of the store.
   * @return description
  **/
  @ApiModelProperty(value = "The description of the store.")

  public String getDescription() {
    return description;
  }


  public void setDescription(String description) {
    this.description = description;
  }


  public UpdateStoreRequest externalReferenceId(String externalReferenceId) {
    
    this.externalReferenceId = externalReferenceId;
    return this;
  }

   /**
   * When using the Zip payment method: The location ID that Zip has assigned to your store.
   * @return externalReferenceId
  **/
  @ApiModelProperty(value = "When using the Zip payment method: The location ID that Zip has assigned to your store.")

  public String getExternalReferenceId() {
    return externalReferenceId;
  }


  public void setExternalReferenceId(String externalReferenceId) {
    this.externalReferenceId = externalReferenceId;
  }


  public UpdateStoreRequest splitConfiguration(StoreSplitConfiguration splitConfiguration) {
    
    this.splitConfiguration = splitConfiguration;
    return this;
  }

   /**
   * Get splitConfiguration
   * @return splitConfiguration
  **/
  @ApiModelProperty(value = "")

  public StoreSplitConfiguration getSplitConfiguration() {
    return splitConfiguration;
  }


  public void setSplitConfiguration(StoreSplitConfiguration splitConfiguration) {
    this.splitConfiguration = splitConfiguration;
  }


  public UpdateStoreRequest status(StatusEnum status) {
    
    this.status = status;
    return this;
  }

   /**
   * The status of the store. Possible values are:  - **active**: This value is assigned automatically when a store is created.  - **inactive**: The maximum [transaction limits and number of Store-and-Forward transactions](https://docs.adyen.com/point-of-sale/determine-account-structure/configure-features#payment-features) for the store are set to 0. This blocks new transactions, but captures are still possible. - **closed**: The terminals of the store are reassigned to the merchant inventory, so they can&#39;t process payments.  You can change the status from **active** to **inactive**, and from **inactive** to **active** or **closed**.  Once **closed**, a store can&#39;t be reopened.
   * @return status
  **/
  @ApiModelProperty(value = "The status of the store. Possible values are:  - **active**: This value is assigned automatically when a store is created.  - **inactive**: The maximum [transaction limits and number of Store-and-Forward transactions](https://docs.adyen.com/point-of-sale/determine-account-structure/configure-features#payment-features) for the store are set to 0. This blocks new transactions, but captures are still possible. - **closed**: The terminals of the store are reassigned to the merchant inventory, so they can't process payments.  You can change the status from **active** to **inactive**, and from **inactive** to **active** or **closed**.  Once **closed**, a store can't be reopened.")

  public StatusEnum getStatus() {
    return status;
  }


  public void setStatus(StatusEnum status) {
    this.status = status;
  }



  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    UpdateStoreRequest updateStoreRequest = (UpdateStoreRequest) o;
    return Objects.equals(this.address, updateStoreRequest.address) &&
        Objects.equals(this.businessLineIds, updateStoreRequest.businessLineIds) &&
        Objects.equals(this.description, updateStoreRequest.description) &&
        Objects.equals(this.externalReferenceId, updateStoreRequest.externalReferenceId) &&
        Objects.equals(this.splitConfiguration, updateStoreRequest.splitConfiguration) &&
        Objects.equals(this.status, updateStoreRequest.status);
  }

  @Override
  public int hashCode() {
    return Objects.hash(address, businessLineIds, description, externalReferenceId, splitConfiguration, status);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class UpdateStoreRequest {\n");
    sb.append("    address: ").append(toIndentedString(address)).append("\n");
    sb.append("    businessLineIds: ").append(toIndentedString(businessLineIds)).append("\n");
    sb.append("    description: ").append(toIndentedString(description)).append("\n");
    sb.append("    externalReferenceId: ").append(toIndentedString(externalReferenceId)).append("\n");
    sb.append("    splitConfiguration: ").append(toIndentedString(splitConfiguration)).append("\n");
    sb.append("    status: ").append(toIndentedString(status)).append("\n");
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


  public static HashSet<String> openapiFields;
  public static HashSet<String> openapiRequiredFields;

  static {
    // a set of all properties/fields (JSON key names)
    openapiFields = new HashSet<String>();
    openapiFields.add("address");
    openapiFields.add("businessLineIds");
    openapiFields.add("description");
    openapiFields.add("externalReferenceId");
    openapiFields.add("splitConfiguration");
    openapiFields.add("status");

    // a set of required properties/fields (JSON key names)
    openapiRequiredFields = new HashSet<String>();
  }

 /**
  * Validates the JSON Object and throws an exception if issues found
  *
  * @param jsonObj JSON Object
  * @throws IOException if the JSON Object is invalid with respect to UpdateStoreRequest
  */
  public static void validateJsonObject(JsonObject jsonObj) throws IOException {
      if (jsonObj == null) {
        if (UpdateStoreRequest.openapiRequiredFields.isEmpty()) {
          return;
        } else { // has required fields
          throw new IllegalArgumentException(String.format("The required field(s) %s in UpdateStoreRequest is not found in the empty JSON string", UpdateStoreRequest.openapiRequiredFields.toString()));
        }
      }

      Set<Entry<String, JsonElement>> entries = jsonObj.entrySet();
      // check to see if the JSON string contains additional fields
      for (Entry<String, JsonElement> entry : entries) {
        if (!UpdateStoreRequest.openapiFields.contains(entry.getKey())) {
          throw new IllegalArgumentException(String.format("The field `%s` in the JSON string is not defined in the `UpdateStoreRequest` properties. JSON: %s", entry.getKey(), jsonObj.toString()));
        }
      }
      // validate the optional field `address`
      if (jsonObj.getAsJsonObject("address") != null) {
        UpdatableAddress.validateJsonObject(jsonObj.getAsJsonObject("address"));
      }
      // ensure the json data is an array
      if (jsonObj.get("businessLineIds") != null && !jsonObj.get("businessLineIds").isJsonArray()) {
        throw new IllegalArgumentException(String.format("Expected the field `businessLineIds` to be an array in the JSON string but got `%s`", jsonObj.get("businessLineIds").toString()));
      }
      // validate the optional field description
      if (jsonObj.get("description") != null && !jsonObj.get("description").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `description` to be a primitive type in the JSON string but got `%s`", jsonObj.get("description").toString()));
      }
      // validate the optional field externalReferenceId
      if (jsonObj.get("externalReferenceId") != null && !jsonObj.get("externalReferenceId").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `externalReferenceId` to be a primitive type in the JSON string but got `%s`", jsonObj.get("externalReferenceId").toString()));
      }
      // validate the optional field `splitConfiguration`
      if (jsonObj.getAsJsonObject("splitConfiguration") != null) {
        StoreSplitConfiguration.validateJsonObject(jsonObj.getAsJsonObject("splitConfiguration"));
      }
      // ensure the field status can be parsed to an enum value
      if (jsonObj.get("status") != null) {
        if(!jsonObj.get("status").isJsonPrimitive()) {
          throw new IllegalArgumentException(String.format("Expected the field `status` to be a primitive type in the JSON string but got `%s`", jsonObj.get("status").toString()));
        }
        StatusEnum.fromValue(jsonObj.get("status").getAsString());
      }
  }

  public static class CustomTypeAdapterFactory implements TypeAdapterFactory {
    @SuppressWarnings("unchecked")
    @Override
    public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
       if (!UpdateStoreRequest.class.isAssignableFrom(type.getRawType())) {
         return null; // this class only serializes 'UpdateStoreRequest' and its subtypes
       }
       final TypeAdapter<JsonElement> elementAdapter = gson.getAdapter(JsonElement.class);
       final TypeAdapter<UpdateStoreRequest> thisAdapter
                        = gson.getDelegateAdapter(this, TypeToken.get(UpdateStoreRequest.class));

       return (TypeAdapter<T>) new TypeAdapter<UpdateStoreRequest>() {
           @Override
           public void write(JsonWriter out, UpdateStoreRequest value) throws IOException {
             JsonObject obj = thisAdapter.toJsonTree(value).getAsJsonObject();
             elementAdapter.write(out, obj);
           }

           @Override
           public UpdateStoreRequest read(JsonReader in) throws IOException {
             JsonObject jsonObj = elementAdapter.read(in).getAsJsonObject();
             validateJsonObject(jsonObj);
             return thisAdapter.fromJsonTree(jsonObj);
           }

       }.nullSafe();
    }
  }

 /**
  * Create an instance of UpdateStoreRequest given an JSON string
  *
  * @param jsonString JSON string
  * @return An instance of UpdateStoreRequest
  * @throws IOException if the JSON string is invalid with respect to UpdateStoreRequest
  */
  public static UpdateStoreRequest fromJson(String jsonString) throws IOException {
    return JSON.getGson().fromJson(jsonString, UpdateStoreRequest.class);
  }

 /**
  * Convert an instance of UpdateStoreRequest to an JSON string
  *
  * @return JSON string
  */
  public String toJson() {
    return JSON.getGson().toJson(this);
  }
}
