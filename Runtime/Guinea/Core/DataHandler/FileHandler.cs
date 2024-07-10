using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Threading.Tasks;

namespace Guinea.Core.DataHandler
{
    public static class FileHandler
    {
        public static void SaveToFile(string filePath, string data)
        {
            File.WriteAllText(filePath, data);
        }

        public static async Task SaveToFileAsync(string filePath, string data, System.Threading.CancellationToken cancellationToken = default)
        {
            await Task.Run(() => File.WriteAllText(filePath, data), cancellationToken); // TODO: Replace with ReadAllTextAsync                   
        }


        public static string ReadFromFile(string filePath) => File.ReadAllText(filePath);

        public static async Task<string> ReadFileAsync(string filePath, System.Threading.CancellationToken cancellationToken = default) => await Task.Run(() => File.ReadAllText(filePath), cancellationToken); // TODO: Replace with ReadAllTextAsync        


        public static byte[] ToByteArray(object instance)
        {
            if (instance == null)
            {
                return null;
            }
            BinaryFormatter formatter = new BinaryFormatter();
            using (MemoryStream ms = new MemoryStream())
            {
                formatter.Serialize(ms, instance);
                return ms.ToArray();
            }
        }
#if !ENABLE_IL2CPP &&NET_4_6
        public static dynamic ByteArrayToObject(byte[] array)
        {
            BinaryFormatter formatter = new BinaryFormatter();
            using (MemoryStream ms = new MemoryStream(array))
            {
                dynamic instance = formatter.Deserialize(ms);
                return instance;
            }
        }
#endif

        public static T ByteArrayToObject<T>(byte[] array)
        {
            BinaryFormatter formatter = new BinaryFormatter();
            using (MemoryStream ms = new MemoryStream(array))
            {
                object instance = formatter.Deserialize(ms);
                return (T)instance;
            }
        }
        public static void SaveToFile(string filePath, object data)
        {
            BinaryFormatter formatter = new BinaryFormatter();
            using (var stream = new FileStream(filePath, FileMode.Create))
            {
                formatter.Serialize(stream, data);
                // Logger.Log($"<color=green>BinaryHandler::SaveToFile() SUCCESS</color>");
            }
        }

#if !ENABLE_IL2CPP && NET_4_6
        public static dynamic ReadFromFile(string filePath)
        {
            // Logger.Assert(File.Exists(filePath), $"<color=red>BinaryHandler::ReadFromFile() FAILED: '{filePath}' not found</color>");
            BinaryFormatter formatter = new BinaryFormatter();
            using (var stream = new FileStream(filePath, FileMode.Open))
            {
                return formatter.Deserialize(stream);
            }
        }
#endif

        public static void SaveToFile<T>(string filePath, T data)
        {
            BinaryFormatter formatter = new BinaryFormatter();
            using (var stream = new FileStream(filePath, FileMode.Create))
            {
                formatter.Serialize(stream, data);
            }
        }

        public static T ReadFromFile<T>(string filePath)
        {
            // Logger.Assert(File.Exists(filePath), $"<color=red>BinaryHandler::ReadFromFile() FAILED: '{filePath}' not found</color>");
            BinaryFormatter formatter = new BinaryFormatter();
            using (var stream = new FileStream(filePath, FileMode.Open))
            {
                return (T)formatter.Deserialize(stream);
            }
        }
    }
}