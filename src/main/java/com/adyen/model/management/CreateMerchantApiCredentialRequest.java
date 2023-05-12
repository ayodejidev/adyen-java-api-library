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
 * CreateMerchantApiCredentialRequest
 */

public class CreateMerchantApiCredentialRequest {
  public static final String SERIALIZED_NAME_ALLOWED_ORIGINS = "allowedOrigins";
  @SerializedName(SERIALIZED_NAME_ALLOWED_ORIGINS)
  private List<String> allowedOrigins = null;

  public static final String SERIALIZED_NAME_DESCRIPTION = "description";
  @SerializedName(SERIALIZED_NAME_DESCRIPTION)
  private String description;

  public static final String SERIALIZED_NAME_ROLES = "roles";
  @SerializedName(SERIALIZED_NAME_ROLES)
  private List<String> roles = null;

  public CreateMerchantApiCredentialRequest() { 
  }

  public CreateMerchantApiCredentialRequest allowedOrigins(List<String> allowedOrigins) {
    
    this.allowedOrigins = allowedOrigins;
    return this;
  }

  public CreateMerchantApiCredentialRequest addAllowedOriginsItem(String allowedOriginsItem) {
    if (this.allowedOrigins == null) {
      this.allowedOrigins = new ArrayList<>();
    }
    this.allowedOrigins.add(allowedOriginsItem);
    return this;
  }

   /**
   * The list of [allowed origins](https://docs.adyen.com/development-resources/client-side-authentication#allowed-origins) for the new API credential.
   * @return allowedOrigins
  **/
  @ApiModelProperty(value = "The list of [allowed origins](https://docs.adyen.com/development-resources/client-side-authentication#allowed-origins) for the new API credential.")

  public List<String> getAllowedOrigins() {
    return allowedOrigins;
  }


  public void setAllowedOrigins(List<String> allowedOrigins) {
    this.allowedOrigins = allowedOrigins;
  }


  public CreateMerchantApiCredentialRequest description(String description) {
    
    this.description = description;
    return this;
  }

   /**
   * Description of the API credential.
   * @return description
  **/
  @ApiModelProperty(value = "Description of the API credential.")

  public String getDescription() {
    return description;
  }


  public void setDescription(String description) {
    this.description = description;
  }


  public CreateMerchantApiCredentialRequest roles(List<String> roles) {
    
    this.roles = roles;
    return this;
  }

  public CreateMerchantApiCredentialRequest addRolesItem(String rolesItem) {
    if (this.roles == null) {
      this.roles = new ArrayList<>();
    }
    this.roles.add(rolesItem);
    return this;
  }

   /**
   * List of [roles](https://docs.adyen.com/development-resources/api-credentials#roles-1) for the API credential.
   * @return roles
  **/
  @ApiModelProperty(value = "List of [roles](https://docs.adyen.com/development-resources/api-credentials#roles-1) for the API credential.")

  public List<String> getRoles() {
    return roles;
  }


  public void setRoles(List<String> roles) {
    this.roles = roles;
  }



  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    CreateMerchantApiCredentialRequest createMerchantApiCredentialRequest = (CreateMerchantApiCredentialRequest) o;
    return Objects.equals(this.allowedOrigins, createMerchantApiCredentialRequest.allowedOrigins) &&
        Objects.equals(this.description, createMerchantApiCredentialRequest.description) &&
        Objects.equals(this.roles, createMerchantApiCredentialRequest.roles);
  }

  @Override
  public int hashCode() {
    return Objects.hash(allowedOrigins, description, roles);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class CreateMerchantApiCredentialRequest {\n");
    sb.append("    allowedOrigins: ").append(toIndentedString(allowedOrigins)).append("\n");
    sb.append("    description: ").append(toIndentedString(description)).append("\n");
    sb.append("    roles: ").append(toIndentedString(roles)).append("\n");
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
    openapiFields.add("allowedOrigins");
    openapiFields.add("description");
    openapiFields.add("roles");

    // a set of required properties/fields (JSON key names)
    openapiRequiredFields = new HashSet<String>();
  }

 /**
  * Validates the JSON Object and throws an exception if issues found
  *
  * @param jsonObj JSON Object
  * @throws IOException if the JSON Object is invalid with respect to CreateMerchantApiCredentialRequest
  */
  public static void validateJsonObject(JsonObject jsonObj) throws IOException {
      if (jsonObj == null) {
        if (CreateMerchantApiCredentialRequest.openapiRequiredFields.isEmpty()) {
          return;
        } else { // has required fields
          throw new IllegalArgumentException(String.format("The required field(s) %s in CreateMerchantApiCredentialRequest is not found in the empty JSON string", CreateMerchantApiCredentialRequest.openapiRequiredFields.toString()));
        }
      }

      Set<Entry<String, JsonElement>> entries = jsonObj.entrySet();
      // check to see if the JSON string contains additional fields
      for (Entry<String, JsonElement> entry : entries) {
        if (!CreateMerchantApiCredentialRequest.openapiFields.contains(entry.getKey())) {
          throw new IllegalArgumentException(String.format("The field `%s` in the JSON string is not defined in the `CreateMerchantApiCredentialRequest` properties. JSON: %s", entry.getKey(), jsonObj.toString()));
        }
      }
      // ensure the json data is an array
      if (jsonObj.get("allowedOrigins") != null && !jsonObj.get("allowedOrigins").isJsonArray()) {
        throw new IllegalArgumentException(String.format("Expected the field `allowedOrigins` to be an array in the JSON string but got `%s`", jsonObj.get("allowedOrigins").toString()));
      }
      // validate the optional field description
      if (jsonObj.get("description") != null && !jsonObj.get("description").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `description` to be a primitive type in the JSON string but got `%s`", jsonObj.get("description").toString()));
      }
      // ensure the json data is an array
      if (jsonObj.get("roles") != null && !jsonObj.get("roles").isJsonArray()) {
        throw new IllegalArgumentException(String.format("Expected the field `roles` to be an array in the JSON string but got `%s`", jsonObj.get("roles").toString()));
      }
  }

  public static class CustomTypeAdapterFactory implements TypeAdapterFactory {
    @SuppressWarnings("unchecked")
    @Override
    public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
       if (!CreateMerchantApiCredentialRequest.class.isAssignableFrom(type.getRawType())) {
         return null; // this class only serializes 'CreateMerchantApiCredentialRequest' and its subtypes
       }
       final TypeAdapter<JsonElement> elementAdapter = gson.getAdapter(JsonElement.class);
       final TypeAdapter<CreateMerchantApiCredentialRequest> thisAdapter
                        = gson.getDelegateAdapter(this, TypeToken.get(CreateMerchantApiCredentialRequest.class));

       return (TypeAdapter<T>) new TypeAdapter<CreateMerchantApiCredentialRequest>() {
           @Override
           public void write(JsonWriter out, CreateMerchantApiCredentialRequest value) throws IOException {
             JsonObject obj = thisAdapter.toJsonTree(value).getAsJsonObject();
             elementAdapter.write(out, obj);
           }

           @Override
           public CreateMerchantApiCredentialRequest read(JsonReader in) throws IOException {
             JsonObject jsonObj = elementAdapter.read(in).getAsJsonObject();
             validateJsonObject(jsonObj);
             return thisAdapter.fromJsonTree(jsonObj);
           }

       }.nullSafe();
    }
  }

 /**
  * Create an instance of CreateMerchantApiCredentialRequest given an JSON string
  *
  * @param jsonString JSON string
  * @return An instance of CreateMerchantApiCredentialRequest
  * @throws IOException if the JSON string is invalid with respect to CreateMerchantApiCredentialRequest
  */
  public static CreateMerchantApiCredentialRequest fromJson(String jsonString) throws IOException {
    return JSON.getGson().fromJson(jsonString, CreateMerchantApiCredentialRequest.class);
  }

 /**
  * Convert an instance of CreateMerchantApiCredentialRequest to an JSON string
  *
  * @return JSON string
  */
  public String toJson() {
    return JSON.getGson().toJson(this);
  }
}
