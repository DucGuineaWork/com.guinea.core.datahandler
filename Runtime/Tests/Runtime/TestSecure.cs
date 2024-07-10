using System.Text;
using NUnit.Framework;

namespace Guinea.Core.DataHandler.Test
{
    public class TestSecure
    {
        private Secure.KeyPair m_keyPair;
        private TestData m_testData;
        private string m_testString;
        
        [SetUp]
        public void SetUp()
        {
            m_keyPair = Secure.GenerateKeyPair();
            m_testData= new TestData()
            {
                name = "Test",
                age = 10,
                address="HanoiVietnam",
                password = 55986896989
            };
            m_testString ="Hello the world";

        }

        [Test]
        public void TestObjectEncryption()
        {
            byte[] encryptedData = Secure.EncryptBytesArray(FileHandler.ToByteArray(m_testData), m_keyPair.publicKey);
            byte[] decryptedData = Secure.DecryptBytesFromBytes(encryptedData, m_keyPair.privateKey);
            TestData data=FileHandler.ByteArrayToObject<TestData>(decryptedData);
            Assert.AreEqual(data.name,"Test");
            Assert.AreEqual(data.age, 10);
            Assert.AreEqual(data.address,"HanoiVietnam");
            Assert.AreEqual(data.password, 55986896989);
        }

        [Test]
        public void TestStringEncryption()
        {
            byte[] encryptedString = Secure.EncryptStringToBytes(m_testString, m_keyPair.publicKey);
            string decryptedString = Secure.DecryptStringFromBytes(encryptedString, m_keyPair.privateKey);
            Assert.AreEqual(m_testString, decryptedString);
        }

        [Test]
        public void TestUTF8Convert()
        {
            byte[] encryptedString= Encoding.UTF8.GetBytes(m_testString);
            string decryptedString = Encoding.UTF8.GetString(encryptedString);
            Assert.AreEqual(m_testString, decryptedString);
        }

        [TearDown]
        public void TearDown()
        {

        }

        [System.Serializable]
        public class TestData
        {
            public string name;
            public uint age;
            public long password;
            public string address;
        }
    }

}