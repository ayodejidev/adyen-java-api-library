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
 * MealVoucherFRInfo
 */

public class MealVoucherFRInfo {
  public static final String SERIALIZED_NAME_CONECS_ID = "conecsId";
  @SerializedName(SERIALIZED_NAME_CONECS_ID)
  private String conecsId;

  public static final String SERIALIZED_NAME_SIRET = "siret";
  @SerializedName(SERIALIZED_NAME_SIRET)
  private String siret;

  public static final String SERIALIZED_NAME_SUB_TYPES = "subTypes";
  @SerializedName(SERIALIZED_NAME_SUB_TYPES)
  private List<String> subTypes = new ArrayList<>();

  public MealVoucherFRInfo() { 
  }

  public MealVoucherFRInfo conecsId(String conecsId) {
    
    this.conecsId = conecsId;
    return this;
  }

   /**
   * Meal Voucher conecsId. Format: digits only
   * @return conecsId
  **/
  @ApiModelProperty(required = true, value = "Meal Voucher conecsId. Format: digits only")

  public String getConecsId() {
    return conecsId;
  }


  public void setConecsId(String conecsId) {
    this.conecsId = conecsId;
  }


  public MealVoucherFRInfo siret(String siret) {
    
    this.siret = siret;
    return this;
  }

   /**
   * Meal Voucher siret. Format: 14 digits.
   * @return siret
  **/
  @ApiModelProperty(required = true, value = "Meal Voucher siret. Format: 14 digits.")

  public String getSiret() {
    return siret;
  }


  public void setSiret(String siret) {
    this.siret = siret;
  }


  public MealVoucherFRInfo subTypes(List<String> subTypes) {
    
    this.subTypes = subTypes;
    return this;
  }

  public MealVoucherFRInfo addSubTypesItem(String subTypesItem) {
    this.subTypes.add(subTypesItem);
    return this;
  }

   /**
   * The list of additional payment methods. Allowed values: **mealVoucher_FR_endenred**, **mealVoucher_FR_groupeup**, **mealVoucher_FR_natixis**, **mealVoucher_FR_sodexo**.
   * @return subTypes
  **/
  @ApiModelProperty(required = true, value = "The list of additional payment methods. Allowed values: **mealVoucher_FR_endenred**, **mealVoucher_FR_groupeup**, **mealVoucher_FR_natixis**, **mealVoucher_FR_sodexo**.")

  public List<String> getSubTypes() {
    return subTypes;
  }


  public void setSubTypes(List<String> subTypes) {
    this.subTypes = subTypes;
  }



  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    MealVoucherFRInfo mealVoucherFRInfo = (MealVoucherFRInfo) o;
    return Objects.equals(this.conecsId, mealVoucherFRInfo.conecsId) &&
        Objects.equals(this.siret, mealVoucherFRInfo.siret) &&
        Objects.equals(this.subTypes, mealVoucherFRInfo.subTypes);
  }

  @Override
  public int hashCode() {
    return Objects.hash(conecsId, siret, subTypes);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class MealVoucherFRInfo {\n");
    sb.append("    conecsId: ").append(toIndentedString(conecsId)).append("\n");
    sb.append("    siret: ").append(toIndentedString(siret)).append("\n");
    sb.append("    subTypes: ").append(toIndentedString(subTypes)).append("\n");
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
    openapiFields.add("conecsId");
    openapiFields.add("siret");
    openapiFields.add("subTypes");

    // a set of required properties/fields (JSON key names)
    openapiRequiredFields = new HashSet<String>();
    openapiRequiredFields.add("conecsId");
    openapiRequiredFields.add("siret");
    openapiRequiredFields.add("subTypes");
  }

 /**
  * Validates the JSON Object and throws an exception if issues found
  *
  * @param jsonObj JSON Object
  * @throws IOException if the JSON Object is invalid with respect to MealVoucherFRInfo
  */
  public static void validateJsonObject(JsonObject jsonObj) throws IOException {
      if (jsonObj == null) {
        if (MealVoucherFRInfo.openapiRequiredFields.isEmpty()) {
          return;
        } else { // has required fields
          throw new IllegalArgumentException(String.format("The required field(s) %s in MealVoucherFRInfo is not found in the empty JSON string", MealVoucherFRInfo.openapiRequiredFields.toString()));
        }
      }

      Set<Entry<String, JsonElement>> entries = jsonObj.entrySet();
      // check to see if the JSON string contains additional fields
      for (Entry<String, JsonElement> entry : entries) {
        if (!MealVoucherFRInfo.openapiFields.contains(entry.getKey())) {
          throw new IllegalArgumentException(String.format("The field `%s` in the JSON string is not defined in the `MealVoucherFRInfo` properties. JSON: %s", entry.getKey(), jsonObj.toString()));
        }
      }

      // check to make sure all required properties/fields are present in the JSON string
      for (String requiredField : MealVoucherFRInfo.openapiRequiredFields) {
        if (jsonObj.get(requiredField) == null) {
          throw new IllegalArgumentException(String.format("The required field `%s` is not found in the JSON string: %s", requiredField, jsonObj.toString()));
        }
      }
      // validate the optional field conecsId
      if (jsonObj.get("conecsId") != null && !jsonObj.get("conecsId").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `conecsId` to be a primitive type in the JSON string but got `%s`", jsonObj.get("conecsId").toString()));
      }
      // validate the optional field siret
      if (jsonObj.get("siret") != null && !jsonObj.get("siret").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `siret` to be a primitive type in the JSON string but got `%s`", jsonObj.get("siret").toString()));
      }
      // ensure the json data is an array
      if (jsonObj.get("subTypes") != null && !jsonObj.get("subTypes").isJsonArray()) {
        throw new IllegalArgumentException(String.format("Expected the field `subTypes` to be an array in the JSON string but got `%s`", jsonObj.get("subTypes").toString()));
      }
  }

  public static class CustomTypeAdapterFactory implements TypeAdapterFactory {
    @SuppressWarnings("unchecked")
    @Override
    public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
       if (!MealVoucherFRInfo.class.isAssignableFrom(type.getRawType())) {
         return null; // this class only serializes 'MealVoucherFRInfo' and its subtypes
       }
       final TypeAdapter<JsonElement> elementAdapter = gson.getAdapter(JsonElement.class);
       final TypeAdapter<MealVoucherFRInfo> thisAdapter
                        = gson.getDelegateAdapter(this, TypeToken.get(MealVoucherFRInfo.class));

       return (TypeAdapter<T>) new TypeAdapter<MealVoucherFRInfo>() {
           @Override
           public void write(JsonWriter out, MealVoucherFRInfo value) throws IOException {
             JsonObject obj = thisAdapter.toJsonTree(value).getAsJsonObject();
             elementAdapter.write(out, obj);
           }

           @Override
           public MealVoucherFRInfo read(JsonReader in) throws IOException {
             JsonObject jsonObj = elementAdapter.read(in).getAsJsonObject();
             validateJsonObject(jsonObj);
             return thisAdapter.fromJsonTree(jsonObj);
           }

       }.nullSafe();
    }
  }

 /**
  * Create an instance of MealVoucherFRInfo given an JSON string
  *
  * @param jsonString JSON string
  * @return An instance of MealVoucherFRInfo
  * @throws IOException if the JSON string is invalid with respect to MealVoucherFRInfo
  */
  public static MealVoucherFRInfo fromJson(String jsonString) throws IOException {
    return JSON.getGson().fromJson(jsonString, MealVoucherFRInfo.class);
  }

 /**
  * Convert an instance of MealVoucherFRInfo to an JSON string
  *
  * @return JSON string
  */
  public String toJson() {
    return JSON.getGson().toJson(this);
  }
}
