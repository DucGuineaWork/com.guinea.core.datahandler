using System;
using UnityEngine;

namespace Guinea.Core.DataHandler
{
    public static class JsonHandler
    {
        private static readonly bool debug = false;
#if !ENABLE_IL2CPP
        public static dynamic Deserialize(string json)
        {
            // Logger.Assert(!String.IsNullOrEmpty(json), $"<color=red>JsonHandler::Deserialize() FAILED: json param can not null or empty</color>");
            try
            {
                dynamic data = JsonUtility.FromJson<dynamic>(json);
                // Logger.LogIf(debug, $"<color=green>JsonHandler::Deserialize() SUCCESS:</color> {data}");
                return data;
            }
            catch (Exception ex)
            {
                // Logger.LogIf(debug,$"<color=red>JsonHandler::Deserialize() FAILED:</color> {ex.Message.ToString()}");
            }
            return default(dynamic);
        }
#endif

        public static T Deserialize<T>(string json)
        {
            // Logger.Assert(!String.IsNullOrEmpty(json), $"<color=red>JsonHandler::Deserialize() FAILED: json param can not null or empty</color>");
            try
            {
                T data = JsonUtility.FromJson<T>(json);
                // Logger.LogIf(debug, $"<color=green>JsonHandler::Deserialize() SUCCESS:</color> {data}");
                return data;
            }
            catch (Exception ex)
            {
                // Logger.LogIf(debug,$"<color=red>JsonHandler::Deserialize() FAILED:</color> {ex.Message.ToString()}");
                return default(T);
            }
        }

        public static string SerializeObject(object o)
        {
            return JsonUtility.ToJson(o);
        }

        // TODO: Implement Asynchronous Serialize and Deserialize
    }
}