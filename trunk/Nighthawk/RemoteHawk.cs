using System;
using System.Collections.Generic;
using System.ServiceModel;
using System.ServiceModel.Description;
using System.Windows;

namespace Nighthawk
{
    [ServiceContract]
    interface IRemoteHawk
    {
        [OperationContract]
        List<string[]> GetCredentials();

        [OperationContract]
        int GetClients();

        [OperationContract]
        string GetNetwork();

        [OperationContract]
        bool GetIPv6Spoofing();
    }

    class RemoteHawk : IRemoteHawk
    {
        public List<string[]> GetCredentials()
        {
            return SharedData.Credentials;
        }
                
        public string GetNetwork()
        {
            return SharedData.Network;
        }
        
        public int GetClients()
        {
            return SharedData.Clients;
        }

        public bool GetIPv6Spoofing()
        {
            return SharedData.IPv6Spoofing;
        }
    }

    class SharedData
    {
        public static List<string[]> Credentials = new List<string[]>();
        public static string Network = "/";
        public static int Clients;
        public static bool IPv6Spoofing;

        public static void Add(string[] data)
        {
            Credentials.Add(data);
        }

        public static void Clear()
        {
            Credentials.Clear();
        }
    }

    class RemoteService
    {
        public static bool Started;
        public static ServiceHost Service;

        public static void Start(string ip)
        {
            var uri = new Uri("http://" + ip + ":51337/remotehawk");

            if (!Started)
            {
                Service = new ServiceHost(typeof(RemoteHawk), uri);

                // metadata
                var smb = new ServiceMetadataBehavior();
                smb.HttpGetEnabled = true;
                smb.MetadataExporter.PolicyVersion = PolicyVersion.Policy15;

                try
                {
                    // start WCF service
                    Service.Description.Behaviors.Add(smb);
                    Service.Open();
                } catch (Exception e)
                {
                    MessageBox.Show("There was an error starting remote control service. " + (e.InnerException != null ? e.InnerException.Message : ""), "Nighthawk",
                                    MessageBoxButton.OK, MessageBoxImage.Exclamation);

                    return;
                }

                Started = true;
            }
        }
    }
}
