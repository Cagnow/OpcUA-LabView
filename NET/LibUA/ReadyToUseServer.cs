using IniParser;
using IniParser.Model;
using LibUA.Core;
using LibUA.Server;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;

namespace LibUA
{
    public class Application : LibUA.Server.Application
        {
        ///*Déclaration des assemblys**
        private readonly ApplicationDescription uaAppDesc;
        private readonly NodeObject ItemsRoot;
        public int test;
        private NodeVariable[] TrendNodes;
        private X509Certificate2 appCertificate = null;
        private RSA cryptPrivateKey = null;
        private List<DataValue> testHistoryPoints = null;
        protected int rowCount = 1;
        protected Random rnd = new Random();
        protected UInt64 nextEventId = 1;
        public static object[] tableau = new object[5];

        
        ///
        public override X509Certificate2 ApplicationCertificate
        {
            get { return appCertificate; }
        }

        public override RSACryptoServiceProvider ApplicationPrivateKey
        {
            get
            {
                if (cryptPrivateKey is RSACryptoServiceProvider rsaCsp)
                {
                    return rsaCsp;
                }
                else
                {
                    throw new InvalidCastException("The private key is not of type RSACryptoServiceProvider.");
                }
            }
        }

        public override object SessionCreate(SessionCreationInfo sessionInfo)
        {
            // Optionally create and return a session object with sessionInfo if you want to track that same object
            // when the client validates its session (anonymous, username + password or certificate).

            return null;
        }

        public override bool SessionValidateClientApplication(object session,

        ApplicationDescription clientApplicationDescription, byte[] clientCertificate, string sessionName)
        {
            // Update your session object with the client's UA application description
            // Return true to allow the client, false to reject

            return true;
        }

        public override void SessionRelease(object session)
        {
        }

        public override bool SessionValidateClientUser(object session, object userIdentityToken)
        {
            if (userIdentityToken is UserIdentityAnonymousToken)
            {
                return true;
            }
            else if (userIdentityToken is UserIdentityUsernameToken)
            {
                _ = (userIdentityToken as UserIdentityUsernameToken).Username;
                _ =
                    (new UTF8Encoding()).GetString((userIdentityToken as UserIdentityUsernameToken).PasswordHash);

                return true;
            }
            return true;
            throw new Exception("Unhandled user identity token type");
        }

        private ApplicationDescription CreateApplicationDescriptionFromEndpointHint(string endpointUrlHint)
        {
            string[] discoveryUrls = uaAppDesc.DiscoveryUrls;
            if (discoveryUrls == null && !string.IsNullOrEmpty(endpointUrlHint))
            {
                discoveryUrls = new string[] { endpointUrlHint };
            }

            return new ApplicationDescription(uaAppDesc.ApplicationUri, uaAppDesc.ProductUri, uaAppDesc.ApplicationName,
                uaAppDesc.Type, uaAppDesc.GatewayServerUri, uaAppDesc.DiscoveryProfileUri, discoveryUrls);
        }
        //Modes d'authentification
        public override IList<EndpointDescription> GetEndpointDescriptions(string endpointUrlHint)
        {
            var certStr = ApplicationCertificate.Export(X509ContentType.Cert);
            ApplicationDescription localAppDesc = CreateApplicationDescriptionFromEndpointHint(endpointUrlHint);

            var epNoSecurity = new EndpointDescription(
                endpointUrlHint, localAppDesc, certStr,
                MessageSecurityMode.None, Types.SLSecurityPolicyUris[(int)SecurityPolicy.None],
                new UserTokenPolicy[]
                {
                         new UserTokenPolicy("0", UserTokenType.Anonymous, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.None]),
                         new UserTokenPolicy("1", UserTokenType.UserName, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256Sha256]),
                }, Types.TransportProfileBinary, 0);

            var epSignBasic128Rsa15 = new EndpointDescription(
                endpointUrlHint, localAppDesc, certStr,
                MessageSecurityMode.Sign, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic128Rsa15],
                new UserTokenPolicy[]
                {
                         new UserTokenPolicy("0", UserTokenType.Anonymous, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.None]),
                         new UserTokenPolicy("1", UserTokenType.UserName, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256Sha256]),
                }, Types.TransportProfileBinary, 0);

            var epSignBasic256 = new EndpointDescription(
                endpointUrlHint, localAppDesc, certStr,
                MessageSecurityMode.Sign, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256],
                new UserTokenPolicy[]
                {
                         new UserTokenPolicy("0", UserTokenType.Anonymous, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.None]),
                         new UserTokenPolicy("1", UserTokenType.UserName, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256Sha256]),
                }, Types.TransportProfileBinary, 0);

            var epSignBasic256Sha256 = new EndpointDescription(
                endpointUrlHint, localAppDesc, certStr,
                MessageSecurityMode.Sign, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256Sha256],
                new UserTokenPolicy[]
                {
                         new UserTokenPolicy("0", UserTokenType.Anonymous, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.None]),
                         new UserTokenPolicy("1", UserTokenType.UserName, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256Sha256]),
                }, Types.TransportProfileBinary, 0);

            /*var epSignRsa128Sha256 = new EndpointDescription(
                endpointUrlHint, localAppDesc, certStr,
                MessageSecurityMode.Sign, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Aes128_Sha256_RsaOaep],
                new UserTokenPolicy[]
                {
                         new UserTokenPolicy("0", UserTokenType.Anonymous, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.None]),
                         new UserTokenPolicy("1", UserTokenType.UserName, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Aes128_Sha256_RsaOaep]),
                }, Types.TransportProfileBinary, 0);*/

            /*var epSignRsa256Sha256 = new EndpointDescription(
                endpointUrlHint, localAppDesc, certStr,
                MessageSecurityMode.Sign, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Aes256_Sha256_RsaPss],
                new UserTokenPolicy[]
                {
                         new UserTokenPolicy("0", UserTokenType.Anonymous, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.None]),
                         new UserTokenPolicy("1", UserTokenType.UserName, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Aes256_Sha256_RsaPss]),
                }, Types.TransportProfileBinary, 0);*/

            var epSignEncryptBasic128Rsa15 = new EndpointDescription(
                endpointUrlHint, localAppDesc, certStr,
                MessageSecurityMode.SignAndEncrypt, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic128Rsa15],
                new UserTokenPolicy[]
                {
                         new UserTokenPolicy("0", UserTokenType.Anonymous, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.None]),
                         new UserTokenPolicy("1", UserTokenType.UserName, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256Sha256]),
                }, Types.TransportProfileBinary, 0);

            var epSignEncryptBasic256 = new EndpointDescription(
                endpointUrlHint, localAppDesc, certStr,
                MessageSecurityMode.SignAndEncrypt, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256],
                new UserTokenPolicy[]
                {
                         new UserTokenPolicy("0", UserTokenType.Anonymous, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.None]),
                         new UserTokenPolicy("1", UserTokenType.UserName, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256Sha256]),
                }, Types.TransportProfileBinary, 0);

            var epSignEncryptBasic256Sha256 = new EndpointDescription(
                endpointUrlHint, localAppDesc, certStr,
                MessageSecurityMode.SignAndEncrypt, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256Sha256],
                new UserTokenPolicy[]
                {
                         new UserTokenPolicy("0", UserTokenType.Anonymous, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.None]),
                         new UserTokenPolicy("1", UserTokenType.UserName, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256Sha256]),
                }, Types.TransportProfileBinary, 0);

            /*var epSignEncryptRsa128Sha256 = new EndpointDescription(
                endpointUrlHint, localAppDesc, certStr,
                MessageSecurityMode.SignAndEncrypt, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Aes128_Sha256_RsaOaep],
                new UserTokenPolicy[]
                {
                         new UserTokenPolicy("0", UserTokenType.Anonymous, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.None]),
                         new UserTokenPolicy("1", UserTokenType.UserName, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Aes128_Sha256_RsaOaep]),
                }, Types.TransportProfileBinary, 0);*/

            /*var epSignEncryptRsa256Sha256 = new EndpointDescription(
                endpointUrlHint, localAppDesc, certStr,
                MessageSecurityMode.SignAndEncrypt, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Aes256_Sha256_RsaPss],
                new UserTokenPolicy[]
                {
                         new UserTokenPolicy("0", UserTokenType.Anonymous, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.None]),
                         new UserTokenPolicy("1", UserTokenType.UserName, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Aes256_Sha256_RsaPss]),
                }, Types.TransportProfileBinary, 0);*/

            return new EndpointDescription[]
            {
                     epNoSecurity,
                     //epSignRsa256Sha256, //epSignEncryptRsa256Sha256,
                     //epSignRsa128Sha256, //epSignEncryptRsa128Sha256,
                     epSignBasic256Sha256, epSignEncryptBasic256Sha256,
                     epSignBasic256, epSignEncryptBasic256,
                     epSignBasic128Rsa15, epSignEncryptBasic128Rsa15
            };
        }

        public override ApplicationDescription GetApplicationDescription(string endpointUrlHint)
        {
            return CreateApplicationDescriptionFromEndpointHint(endpointUrlHint);
        }

        protected override DataValue HandleReadRequestInternal(NodeId id)
        {
            //object value;
            DataValue dataValue;
            if (id.NamespaceIndex == 2 /*&&
               AddressSpaceTable.TryGetValue(id, out Node node)*/)
            {
                dataValue = new DataValue(tableau[id.NumericIdentifier - 2], new StatusCode?(StatusCode.Good), DateTime.UtcNow, null);
            }
            else
            {
                dataValue = new DataValue(null, new StatusCode?(StatusCode.Good), DateTime.UtcNow, null);
            }
            return dataValue;
        }

        /* public void PlayRow(string test1)
         {
             foreach (var nodes in TrendNodes)
             {
                 if (nodes.Id.NamespaceIndex == 2 &&
                     AddressSpaceTable.TryGetValue(nodes, out Node node))
                 {

                     new DataValue(test1, StatusCode.Good, DateTime.UtcNow);

                 }
             }
         }*/

        

        public override UInt32 HandleHistoryReadRequest(object session, object readDetails, HistoryReadValueId id,
                ContinuationPointHistory continuationPoint, List<DataValue> results, ref int? offsetContinueFit)
        {
            if (testHistoryPoints == null)
            {
                testHistoryPoints = new List<DataValue>();

                var dt = new DateTime(2015, 12, 1);
                for (int i = 0; i < 100000; i++)
                {
                    testHistoryPoints.Add(new DataValue(
                        Math.Sin(i * 0.3) + Math.Cos(i * 0.17) * 0.5 + Math.Sin(i * 0.087) * 0.25, StatusCode.Good,
                        dt));
                    dt = dt.AddHours(1);
                }
            }

            int startOffset = continuationPoint.IsValid ? continuationPoint.Offset : 0;
            if (readDetails is ReadRawModifiedDetails)
            {
                var rd = readDetails as ReadRawModifiedDetails;
                for (int i = 0; i < 100000; i++)
                {
                    var p = testHistoryPoints[i];
                    if (p.SourceTimestamp >= rd.StartTime &&
                        p.SourceTimestamp < rd.EndTime)
                    {
                        // Skip startOffset points
                        if (startOffset > 0)
                        {
                            startOffset--;
                            continue;
                        }

                        results.Add(p);
                    }
                }

                return (UInt32)StatusCode.Good;
            }

            return (UInt32)StatusCode.BadHistoryOperationUnsupported;
        }

        public override UInt32 HandleHistoryEventReadRequest(object session, object readDetails,
               HistoryReadValueId id, ContinuationPointHistory continuationPoint, List<object[]> results)
        {
            if (readDetails is ReadEventDetails)
            {
                var rd = readDetails as ReadEventDetails;

                var dt = rd.StartTime;
                for (int i = 0; i < 5; i++)
                {
                    var ev = GenerateSampleAlarmEvent(dt);
                    results.Add(NetDispatcher.MatchFilterClauses(rd.SelectClauses, ev));
                    dt = dt.AddMinutes(1);
                }

                return (UInt32)StatusCode.Good;
            }

            return (UInt32)StatusCode.BadHistoryOperationUnsupported;
        }

        private EventNotification GenerateSampleAlarmEvent(DateTime eventTime)
        {
            return new EventNotification(new EventNotification.Field[]
            {
					// During publishing, operand BrowsePaths are matched
					// against UA select clauses from the subscriber.
					// The operands shown here are the most common requested (90% of cases).
					// Types match operand BrowsePath, do not change them and remember
					// casting when passing into a variant.

					new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
                            new[] {new QualifiedName("EventId")}
                        ),
                        Value = nextEventId
                    },
                    new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
                            new[] {new QualifiedName("EventType")}
                        ),
                        Value = new NodeId(UAConst.ExclusiveLevelAlarmType)
                    },
                    new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
                            new[] {new QualifiedName("SourceName")}
                        ),
                        Value = "Source name"
                    },
                    new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
                            new[] {new QualifiedName("Time")}
                        ),
                        Value = eventTime,
                    },
                    new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
                            new[] {new QualifiedName("Message")}
                        ),
                        Value = new LocalizedText("Event message")
                    },
                    new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
                            new[] {new QualifiedName("Severity")}
                        ),
						// Severity is 0 to 1000
						Value = (UInt16) (rnd.Next() % 1000)
                    },
					// ActiveState object is a name, Id gives the value specified by the name
					// The names do not mean anything (just display text), but Id is important
					new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
                            new[] {new QualifiedName("ActiveState")}
                        ),
                        Value = new LocalizedText("Active")
                    },
                    new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
							// Represents ActiveState.Id
							new[] {new QualifiedName("ActiveState"), new QualifiedName("Id")}
                        ),
						// Inactive specifies false, Active specifies true
						Value = true
                    },
                    new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
                            new[] {new QualifiedName("ActiveState"), new QualifiedName("EffectiveDisplayName")}
                        ),
                        Value = new LocalizedText("Alarm active")
                    },
					// Same rules for AckedState
					new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
                            new[] {new QualifiedName("AckedState")}
                        ),
                        Value = new LocalizedText("Acknowledged")
                    },
                    new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
							// Represents AckedState.Id
							new[] {new QualifiedName("AckedState"), new QualifiedName("Id")}
                        ),
						// Inactive specifies false, Active specifies true
						Value = true,
                    },
                    new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
                            new[] {new QualifiedName("Retain")}
                        ),
                        Value = true
                    },
                    new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
                            new[] {new QualifiedName("ConditionName")}
                        ),
                        Value = "Sample alarm"
                    },
					// Necessary field for alarms
					new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
                            NodeId.Zero, new[] {new QualifiedName("ConditionType")},
                            NodeAttribute.NodeId, null
                        ),
                        Value = NodeId.Zero
                    },
            });
        }
      
        private void LoadCertificateAndPrivateKey()
        {
            try
            {
                // Try to load existing (public key) and associated private key
                appCertificate = new X509Certificate2("ServerCert.der");
                cryptPrivateKey = RSA.Create();
                cryptPrivateKey.KeySize = 2048;

                var rsaPrivParams = UASecurity.ImportRSAPrivateKey(File.ReadAllText("ServerKey.pem"));
                cryptPrivateKey.ImportParameters(rsaPrivParams);
            }
            catch
            {
                // Make a new certificate (public key) and associated private key
                var dn = new X500DistinguishedName("CN=Server certificate;OU=Demo organization",
                    X500DistinguishedNameFlags.UseSemicolons);
                SubjectAlternativeNameBuilder sanBuilder = new SubjectAlternativeNameBuilder();
                sanBuilder.AddUri(new Uri("urn:Application"));

                using (RSA rsa = RSA.Create(4096))
                {
                    var request = new CertificateRequest(dn, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                    request.CertificateExtensions.Add(sanBuilder.Build());
                    request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
                    request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

                    request.CertificateExtensions.Add(new X509KeyUsageExtension(
                        X509KeyUsageFlags.DigitalSignature |
                        X509KeyUsageFlags.NonRepudiation |
                        X509KeyUsageFlags.DataEncipherment |
                        X509KeyUsageFlags.KeyEncipherment, false));

                    request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection {
                            new Oid("1.3.6.1.5.5.7.3.8"),
                            new Oid("1.3.6.1.5.5.7.3.1"),
                            new Oid("1.3.6.1.5.5.7.3.2"),
                            new Oid("1.3.6.1.5.5.7.3.3"),
                            new Oid("1.3.6.1.5.5.7.3.4"),
                            new Oid("1.3.6.1.5.5.7.3.8"),
                            new Oid("1.3.6.1.5.5.7.3.9"),
                        }, true));

                    var certificate = request.CreateSelfSigned(new DateTimeOffset(DateTime.UtcNow.AddDays(-1)),
                        new DateTimeOffset(DateTime.UtcNow.AddDays(3650)));

                    appCertificate = new X509Certificate2(certificate.Export(X509ContentType.Pfx, ""),
                        "", X509KeyStorageFlags.DefaultKeySet);

                    var certPrivateParams = rsa.ExportParameters(true);
                    File.WriteAllText("ServerCert.der", UASecurity.ExportPEM(appCertificate));
                    File.WriteAllText("ServerKey.pem", UASecurity.ExportRSAPrivateKey(certPrivateParams));

                    cryptPrivateKey = RSA.Create();
                    cryptPrivateKey.KeySize = 2048;
                    cryptPrivateKey.ImportParameters(certPrivateParams);
                }
            }
        }

        public  Application(string appname,string cheminconf)
        {
            LoadCertificateAndPrivateKey();

            uaAppDesc = new ApplicationDescription(
                "urn:Application", "",
                new LocalizedText("fr-FR", appname), ApplicationType.Server,
                null, null, null);

            ItemsRoot = new NodeObject(new NodeId(2, 0), new QualifiedName("OPTEC"), new LocalizedText("OPTEC"),
                new LocalizedText("OTPEC"), 0, 0, 0);

            if (AddressSpaceTable.TryGetValue(new NodeId(UAConst.ObjectsFolder), out Node objectsFolderNode))
            {
                objectsFolderNode.References.Add(new ReferenceNode(new NodeId(UAConst.Organizes), ItemsRoot.Id, false));
                ItemsRoot.References.Add(new ReferenceNode(new NodeId(UAConst.Organizes), new NodeId(UAConst.ObjectsFolder), true));
            }
            else
            {
                Console.WriteLine($"NodeId {UAConst.ObjectsFolder} not found in AddressSpaceTable.");
            }

            // Always add ItemsRoot to the AddressSpaceTable
            AddressSpaceTable.TryAdd(ItemsRoot.Id, ItemsRoot);

            // Load nodes from the provided INI configuration
            LoadNodesFromIni(cheminconf);

        }

        public static LibUA.Server.Master StartServer(string appname,Int32 port,string cheminconf)
        {
            var app = new Application(appname,cheminconf);
            var logger = default(ILogger);
            var server = new LibUA.Server.Master(app, port, 10, 30, 100, logger);
                server.Start();

            return server;
        }

        public class NodeConfig
        {
            public uint NodeId { get; set; }
            public string Name { get; set; }
            public string Type { get; set; }
        }

        void LoadNodesFromIni(string configFilePath)
        {

            var parser = new FileIniDataParser();
            IniData data = parser.ReadFile(configFilePath);

            TrendNodes = new NodeVariable[data.Sections.Count];
            int i = 0;
            tableau[0] = "def";
            tableau[1] = "def1";
            tableau[2] = 0f;
            tableau[3] = 0f;
            tableau[4] = 0f;
            foreach (var section in data.Sections)
            {
                var nodeConfig = section.Keys;
                uint nodeIdValue = uint.Parse(nodeConfig["NodeId"]);
                string nodeName = nodeConfig["Name"];
                string nodeType = nodeConfig["Type"];

                // Create NodeId with Address Space = 2 (following your original code structure)
                NodeId nodeId = new NodeId(2, nodeIdValue);
                NodeId nodeTypeId;

                //Types à declarer 
                if (nodeType.Equals("Bool", StringComparison.OrdinalIgnoreCase))
                {
                    nodeTypeId = new NodeId(0, 1);
                }
                else if (nodeType.Equals("SByte", StringComparison.OrdinalIgnoreCase))
                {
                    nodeTypeId = new NodeId(0, 2);
                }
                else if (nodeType.Equals("Byte", StringComparison.OrdinalIgnoreCase))
                {
                    nodeTypeId = new NodeId(0, 3);
                }
                else if (nodeType.Equals("Int16", StringComparison.OrdinalIgnoreCase))
                {
                    nodeTypeId = new NodeId(0, 4);
                }
                else if (nodeType.Equals("UInt16", StringComparison.OrdinalIgnoreCase))
                {
                    nodeTypeId = new NodeId(0, 5);
                }
                if (nodeType.Equals("String", StringComparison.OrdinalIgnoreCase))
                {
                    nodeTypeId = new NodeId(0, 12);
                }
                else if (nodeType.Equals("Float", StringComparison.OrdinalIgnoreCase))
                {
                    nodeTypeId = new NodeId(0, 10);
                }
                else if (nodeType.Equals("Variant", StringComparison.OrdinalIgnoreCase))
                {
                    nodeTypeId = new NodeId(0, 24);
                }
                else
                {
                    throw new ArgumentException($"Type non supporté ou non reconnu {nodeType}");
                }

                // Create the NodeVariable instance
                TrendNodes[i] = new NodeVariable(
                    nodeId,
                    new QualifiedName(nodeName),
                    new LocalizedText(nodeName),
                    new LocalizedText(nodeName),
                    0,
                    0,
                    AccessLevel.CurrentWrite | AccessLevel.HistoryWrite,
                    AccessLevel.CurrentWrite | AccessLevel.HistoryWrite,
                    0,
                    true,
                    nodeTypeId
                );

                // Add references
                ItemsRoot.References.Add(new ReferenceNode(new NodeId(UAConst.Organizes), TrendNodes[i].Id, false));
                TrendNodes[i].References.Add(new ReferenceNode(new NodeId(UAConst.Organizes), ItemsRoot.Id, true));

                // Add to AddressSpaceTable
                AddressSpaceTable[TrendNodes[i].Id] = TrendNodes[i];
                i++;
            }

        }
        
        public string GetValue(int index)
         {
            {
                string ret = "";
                Type t = tableau[index].GetType();
                if (t.Equals(typeof(float)))
                    ret = tableau[index].ToString();
                else if (t.Equals(typeof(string)))
                    ret = tableau[index].ToString();
                return ret;
            }

        }
        
        public void SetValue(int index, string value)
        {
            Type t =tableau[index].GetType();
            if (t.Equals(typeof(float)))
                tableau[index] = float.Parse(value);
            else if (t.Equals(typeof(string)))
                tableau[index] = value;
        }

        public void StopServer(LibUA.Server.Master server)
        {
            server.Stop();
        }

        public override uint[] HandleWriteRequest(object session, WriteValue[] writeValues)
        {
            uint[] respStatus = new uint[writeValues.Length];
            int i = 0;
            foreach (var node in writeValues)
            {
                if (node.NodeId.NamespaceIndex == 2)
                {
                    tableau[node.NodeId.NumericIdentifier - 2] = node.Value.Value;
                    respStatus[i] = 0U;
                }
                else
                {
                    respStatus[i] = 2151350272U;
                }
                i++;
            }
            return respStatus;
        }

        public static void Main(string[] args)
        { 
            Master master = StartServer("OPTEC-DEBUGVS",7718,"cfg.ini");
            //master.App.SessionValidateClientUser()
           // tableau[0] = Convert.ToString(Console.ReadLine());
        }
    }
         
        
    }
