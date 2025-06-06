/**
 * <auto-generated>
 * Autogenerated by Thrift Compiler (0.21.0)
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 * </auto-generated>
 */
using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Thrift;
using Thrift.Collections;
using Thrift.Protocol;
using Thrift.Protocol.Entities;
using Thrift.Protocol.Utilities;
using Thrift.Transport;
using Thrift.Transport.Client;
using Thrift.Transport.Server;
using Thrift.Processor;


// targeting netstandard 2.x
#if(! NETSTANDARD2_0_OR_GREATER && ! NET6_0_OR_GREATER && ! NET472_OR_GREATER)
#error Unexpected target platform. See 'thrift --help' for details.
#endif

#pragma warning disable IDE0079  // remove unnecessary pragmas
#pragma warning disable IDE0017  // object init can be simplified
#pragma warning disable IDE0028  // collection init can be simplified
#pragma warning disable IDE1006  // parts of the code use IDL spelling
#pragma warning disable CA1822   // empty DeepCopy() methods still non-static
#pragma warning disable CS0618   // silence our own deprecation warnings
#pragma warning disable IDE0083  // pattern matching "that is not SomeType" requires net5.0 but we still support earlier versions

namespace Apache.Hive.Service.Rpc.Thrift
{

  internal partial class TOpenSessionReq : TBase
  {
    private global::Apache.Hive.Service.Rpc.Thrift.TProtocolVersion _client_protocol;
    private string _username;
    private string _password;
    private Dictionary<string, string> _configuration;
    private List<global::Apache.Hive.Service.Rpc.Thrift.TGetInfoType> _getInfos;
    private long _client_protocol_i64;
    private Dictionary<string, string> _connectionProperties;
    private global::Apache.Hive.Service.Rpc.Thrift.TNamespace _initialNamespace;
    private bool _canUseMultipleCatalogs;

    /// <summary>
    ///
    /// <seealso cref="global::Apache.Hive.Service.Rpc.Thrift.TProtocolVersion"/>
    /// </summary>
    public global::Apache.Hive.Service.Rpc.Thrift.TProtocolVersion Client_protocol
    {
      get
      {
        return _client_protocol;
      }
      set
      {
        __isset.client_protocol = true;
        this._client_protocol = value;
      }
    }

    public string Username
    {
      get
      {
        return _username;
      }
      set
      {
        __isset.@username = true;
        this._username = value;
      }
    }

    public string Password
    {
      get
      {
        return _password;
      }
      set
      {
        __isset.@password = true;
        this._password = value;
      }
    }

    public Dictionary<string, string> Configuration
    {
      get
      {
        return _configuration;
      }
      set
      {
        __isset.@configuration = true;
        this._configuration = value;
      }
    }

    public List<global::Apache.Hive.Service.Rpc.Thrift.TGetInfoType> GetInfos
    {
      get
      {
        return _getInfos;
      }
      set
      {
        __isset.getInfos = true;
        this._getInfos = value;
      }
    }

    public long Client_protocol_i64
    {
      get
      {
        return _client_protocol_i64;
      }
      set
      {
        __isset.client_protocol_i64 = true;
        this._client_protocol_i64 = value;
      }
    }

    public Dictionary<string, string> ConnectionProperties
    {
      get
      {
        return _connectionProperties;
      }
      set
      {
        __isset.connectionProperties = true;
        this._connectionProperties = value;
      }
    }

    public global::Apache.Hive.Service.Rpc.Thrift.TNamespace InitialNamespace
    {
      get
      {
        return _initialNamespace;
      }
      set
      {
        __isset.initialNamespace = true;
        this._initialNamespace = value;
      }
    }

    public bool CanUseMultipleCatalogs
    {
      get
      {
        return _canUseMultipleCatalogs;
      }
      set
      {
        __isset.canUseMultipleCatalogs = true;
        this._canUseMultipleCatalogs = value;
      }
    }


    public Isset __isset;
    public struct Isset
    {
      public bool client_protocol;
      public bool @username;
      public bool @password;
      public bool @configuration;
      public bool getInfos;
      public bool client_protocol_i64;
      public bool connectionProperties;
      public bool initialNamespace;
      public bool canUseMultipleCatalogs;
    }

    public TOpenSessionReq()
    {
      this._client_protocol = global::Apache.Hive.Service.Rpc.Thrift.TProtocolVersion.__HIVE_JDBC_WORKAROUND;
      this.__isset.client_protocol = true;
    }

    public async global::System.Threading.Tasks.Task ReadAsync(TProtocol iprot, CancellationToken cancellationToken)
    {
      iprot.IncrementRecursionDepth();
      try
      {
        TField field;
        await iprot.ReadStructBeginAsync(cancellationToken);
        while (true)
        {
          field = await iprot.ReadFieldBeginAsync(cancellationToken);
          if (field.Type == TType.Stop)
          {
            break;
          }

          switch (field.ID)
          {
            case 1:
              if (field.Type == TType.I32)
              {
                Client_protocol = (global::Apache.Hive.Service.Rpc.Thrift.TProtocolVersion)await iprot.ReadI32Async(cancellationToken);
              }
              else
              {
                await TProtocolUtil.SkipAsync(iprot, field.Type, cancellationToken);
              }
              break;
            case 2:
              if (field.Type == TType.String)
              {
                Username = await iprot.ReadStringAsync(cancellationToken);
              }
              else
              {
                await TProtocolUtil.SkipAsync(iprot, field.Type, cancellationToken);
              }
              break;
            case 3:
              if (field.Type == TType.String)
              {
                Password = await iprot.ReadStringAsync(cancellationToken);
              }
              else
              {
                await TProtocolUtil.SkipAsync(iprot, field.Type, cancellationToken);
              }
              break;
            case 4:
              if (field.Type == TType.Map)
              {
                {
                  var _map316 = await iprot.ReadMapBeginAsync(cancellationToken);
                  Configuration = new Dictionary<string, string>(_map316.Count);
                  for(int _i317 = 0; _i317 < _map316.Count; ++_i317)
                  {
                    string _key318;
                    string _val319;
                    _key318 = await iprot.ReadStringAsync(cancellationToken);
                    _val319 = await iprot.ReadStringAsync(cancellationToken);
                    Configuration[_key318] = _val319;
                  }
                  await iprot.ReadMapEndAsync(cancellationToken);
                }
              }
              else
              {
                await TProtocolUtil.SkipAsync(iprot, field.Type, cancellationToken);
              }
              break;
            case 1281:
              if (field.Type == TType.List)
              {
                {
                  var _list320 = await iprot.ReadListBeginAsync(cancellationToken);
                  GetInfos = new List<global::Apache.Hive.Service.Rpc.Thrift.TGetInfoType>(_list320.Count);
                  for(int _i321 = 0; _i321 < _list320.Count; ++_i321)
                  {
                    global::Apache.Hive.Service.Rpc.Thrift.TGetInfoType _elem322;
                    _elem322 = (global::Apache.Hive.Service.Rpc.Thrift.TGetInfoType)await iprot.ReadI32Async(cancellationToken);
                    GetInfos.Add(_elem322);
                  }
                  await iprot.ReadListEndAsync(cancellationToken);
                }
              }
              else
              {
                await TProtocolUtil.SkipAsync(iprot, field.Type, cancellationToken);
              }
              break;
            case 1282:
              if (field.Type == TType.I64)
              {
                Client_protocol_i64 = await iprot.ReadI64Async(cancellationToken);
              }
              else
              {
                await TProtocolUtil.SkipAsync(iprot, field.Type, cancellationToken);
              }
              break;
            case 1283:
              if (field.Type == TType.Map)
              {
                {
                  var _map323 = await iprot.ReadMapBeginAsync(cancellationToken);
                  ConnectionProperties = new Dictionary<string, string>(_map323.Count);
                  for(int _i324 = 0; _i324 < _map323.Count; ++_i324)
                  {
                    string _key325;
                    string _val326;
                    _key325 = await iprot.ReadStringAsync(cancellationToken);
                    _val326 = await iprot.ReadStringAsync(cancellationToken);
                    ConnectionProperties[_key325] = _val326;
                  }
                  await iprot.ReadMapEndAsync(cancellationToken);
                }
              }
              else
              {
                await TProtocolUtil.SkipAsync(iprot, field.Type, cancellationToken);
              }
              break;
            case 1284:
              if (field.Type == TType.Struct)
              {
                InitialNamespace = new global::Apache.Hive.Service.Rpc.Thrift.TNamespace();
                await InitialNamespace.ReadAsync(iprot, cancellationToken);
              }
              else
              {
                await TProtocolUtil.SkipAsync(iprot, field.Type, cancellationToken);
              }
              break;
            case 1285:
              if (field.Type == TType.Bool)
              {
                CanUseMultipleCatalogs = await iprot.ReadBoolAsync(cancellationToken);
              }
              else
              {
                await TProtocolUtil.SkipAsync(iprot, field.Type, cancellationToken);
              }
              break;
            default:
              await TProtocolUtil.SkipAsync(iprot, field.Type, cancellationToken);
              break;
          }

          await iprot.ReadFieldEndAsync(cancellationToken);
        }

        await iprot.ReadStructEndAsync(cancellationToken);
      }
      finally
      {
        iprot.DecrementRecursionDepth();
      }
    }

    public async global::System.Threading.Tasks.Task WriteAsync(TProtocol oprot, CancellationToken cancellationToken)
    {
      oprot.IncrementRecursionDepth();
      try
      {
        var tmp327 = new TStruct("TOpenSessionReq");
        await oprot.WriteStructBeginAsync(tmp327, cancellationToken);
        var tmp328 = new TField();
        if(__isset.client_protocol)
        {
          tmp328.Name = "client_protocol";
          tmp328.Type = TType.I32;
          tmp328.ID = 1;
          await oprot.WriteFieldBeginAsync(tmp328, cancellationToken);
          await oprot.WriteI32Async((int)Client_protocol, cancellationToken);
          await oprot.WriteFieldEndAsync(cancellationToken);
        }
        if((Username != null) && __isset.@username)
        {
          tmp328.Name = "username";
          tmp328.Type = TType.String;
          tmp328.ID = 2;
          await oprot.WriteFieldBeginAsync(tmp328, cancellationToken);
          await oprot.WriteStringAsync(Username, cancellationToken);
          await oprot.WriteFieldEndAsync(cancellationToken);
        }
        if((Password != null) && __isset.@password)
        {
          tmp328.Name = "password";
          tmp328.Type = TType.String;
          tmp328.ID = 3;
          await oprot.WriteFieldBeginAsync(tmp328, cancellationToken);
          await oprot.WriteStringAsync(Password, cancellationToken);
          await oprot.WriteFieldEndAsync(cancellationToken);
        }
        if((Configuration != null) && __isset.@configuration)
        {
          tmp328.Name = "configuration";
          tmp328.Type = TType.Map;
          tmp328.ID = 4;
          await oprot.WriteFieldBeginAsync(tmp328, cancellationToken);
          await oprot.WriteMapBeginAsync(new TMap(TType.String, TType.String, Configuration.Count), cancellationToken);
          foreach (string _iter329 in Configuration.Keys)
          {
            await oprot.WriteStringAsync(_iter329, cancellationToken);
            await oprot.WriteStringAsync(Configuration[_iter329], cancellationToken);
          }
          await oprot.WriteMapEndAsync(cancellationToken);
          await oprot.WriteFieldEndAsync(cancellationToken);
        }
        if((GetInfos != null) && __isset.getInfos)
        {
          tmp328.Name = "getInfos";
          tmp328.Type = TType.List;
          tmp328.ID = 1281;
          await oprot.WriteFieldBeginAsync(tmp328, cancellationToken);
          await oprot.WriteListBeginAsync(new TList(TType.I32, GetInfos.Count), cancellationToken);
          foreach (global::Apache.Hive.Service.Rpc.Thrift.TGetInfoType _iter330 in GetInfos)
          {
            await oprot.WriteI32Async((int)_iter330, cancellationToken);
          }
          await oprot.WriteListEndAsync(cancellationToken);
          await oprot.WriteFieldEndAsync(cancellationToken);
        }
        if(__isset.client_protocol_i64)
        {
          tmp328.Name = "client_protocol_i64";
          tmp328.Type = TType.I64;
          tmp328.ID = 1282;
          await oprot.WriteFieldBeginAsync(tmp328, cancellationToken);
          await oprot.WriteI64Async(Client_protocol_i64, cancellationToken);
          await oprot.WriteFieldEndAsync(cancellationToken);
        }
        if((ConnectionProperties != null) && __isset.connectionProperties)
        {
          tmp328.Name = "connectionProperties";
          tmp328.Type = TType.Map;
          tmp328.ID = 1283;
          await oprot.WriteFieldBeginAsync(tmp328, cancellationToken);
          await oprot.WriteMapBeginAsync(new TMap(TType.String, TType.String, ConnectionProperties.Count), cancellationToken);
          foreach (string _iter331 in ConnectionProperties.Keys)
          {
            await oprot.WriteStringAsync(_iter331, cancellationToken);
            await oprot.WriteStringAsync(ConnectionProperties[_iter331], cancellationToken);
          }
          await oprot.WriteMapEndAsync(cancellationToken);
          await oprot.WriteFieldEndAsync(cancellationToken);
        }
        if((InitialNamespace != null) && __isset.initialNamespace)
        {
          tmp328.Name = "initialNamespace";
          tmp328.Type = TType.Struct;
          tmp328.ID = 1284;
          await oprot.WriteFieldBeginAsync(tmp328, cancellationToken);
          await InitialNamespace.WriteAsync(oprot, cancellationToken);
          await oprot.WriteFieldEndAsync(cancellationToken);
        }
        if(__isset.canUseMultipleCatalogs)
        {
          tmp328.Name = "canUseMultipleCatalogs";
          tmp328.Type = TType.Bool;
          tmp328.ID = 1285;
          await oprot.WriteFieldBeginAsync(tmp328, cancellationToken);
          await oprot.WriteBoolAsync(CanUseMultipleCatalogs, cancellationToken);
          await oprot.WriteFieldEndAsync(cancellationToken);
        }
        await oprot.WriteFieldStopAsync(cancellationToken);
        await oprot.WriteStructEndAsync(cancellationToken);
      }
      finally
      {
        oprot.DecrementRecursionDepth();
      }
    }

    public override bool Equals(object that)
    {
      if (!(that is TOpenSessionReq other)) return false;
      if (ReferenceEquals(this, other)) return true;
      return ((__isset.client_protocol == other.__isset.client_protocol) && ((!__isset.client_protocol) || (global::System.Object.Equals(Client_protocol, other.Client_protocol))))
        && ((__isset.@username == other.__isset.@username) && ((!__isset.@username) || (global::System.Object.Equals(Username, other.Username))))
        && ((__isset.@password == other.__isset.@password) && ((!__isset.@password) || (global::System.Object.Equals(Password, other.Password))))
        && ((__isset.@configuration == other.__isset.@configuration) && ((!__isset.@configuration) || (TCollections.Equals(Configuration, other.Configuration))))
        && ((__isset.getInfos == other.__isset.getInfos) && ((!__isset.getInfos) || (TCollections.Equals(GetInfos, other.GetInfos))))
        && ((__isset.client_protocol_i64 == other.__isset.client_protocol_i64) && ((!__isset.client_protocol_i64) || (global::System.Object.Equals(Client_protocol_i64, other.Client_protocol_i64))))
        && ((__isset.connectionProperties == other.__isset.connectionProperties) && ((!__isset.connectionProperties) || (TCollections.Equals(ConnectionProperties, other.ConnectionProperties))))
        && ((__isset.initialNamespace == other.__isset.initialNamespace) && ((!__isset.initialNamespace) || (global::System.Object.Equals(InitialNamespace, other.InitialNamespace))))
        && ((__isset.canUseMultipleCatalogs == other.__isset.canUseMultipleCatalogs) && ((!__isset.canUseMultipleCatalogs) || (global::System.Object.Equals(CanUseMultipleCatalogs, other.CanUseMultipleCatalogs))));
    }

    public override int GetHashCode() {
      int hashcode = 157;
      unchecked {
        if(__isset.client_protocol)
        {
          hashcode = (hashcode * 397) + Client_protocol.GetHashCode();
        }
        if((Username != null) && __isset.@username)
        {
          hashcode = (hashcode * 397) + Username.GetHashCode();
        }
        if((Password != null) && __isset.@password)
        {
          hashcode = (hashcode * 397) + Password.GetHashCode();
        }
        if((Configuration != null) && __isset.@configuration)
        {
          hashcode = (hashcode * 397) + TCollections.GetHashCode(Configuration);
        }
        if((GetInfos != null) && __isset.getInfos)
        {
          hashcode = (hashcode * 397) + TCollections.GetHashCode(GetInfos);
        }
        if(__isset.client_protocol_i64)
        {
          hashcode = (hashcode * 397) + Client_protocol_i64.GetHashCode();
        }
        if((ConnectionProperties != null) && __isset.connectionProperties)
        {
          hashcode = (hashcode * 397) + TCollections.GetHashCode(ConnectionProperties);
        }
        if((InitialNamespace != null) && __isset.initialNamespace)
        {
          hashcode = (hashcode * 397) + InitialNamespace.GetHashCode();
        }
        if(__isset.canUseMultipleCatalogs)
        {
          hashcode = (hashcode * 397) + CanUseMultipleCatalogs.GetHashCode();
        }
      }
      return hashcode;
    }

    public override string ToString()
    {
      var tmp332 = new StringBuilder("TOpenSessionReq(");
      int tmp333 = 0;
      if(__isset.client_protocol)
      {
        if(0 < tmp333++) { tmp332.Append(", "); }
        tmp332.Append("Client_protocol: ");
        Client_protocol.ToString(tmp332);
      }
      if((Username != null) && __isset.@username)
      {
        if(0 < tmp333++) { tmp332.Append(", "); }
        tmp332.Append("Username: ");
        Username.ToString(tmp332);
      }
      if((Password != null) && __isset.@password)
      {
        if(0 < tmp333++) { tmp332.Append(", "); }
        tmp332.Append("Password: ");
        Password.ToString(tmp332);
      }
      if((Configuration != null) && __isset.@configuration)
      {
        if(0 < tmp333++) { tmp332.Append(", "); }
        tmp332.Append("Configuration: ");
        Configuration.ToString(tmp332);
      }
      if((GetInfos != null) && __isset.getInfos)
      {
        if(0 < tmp333++) { tmp332.Append(", "); }
        tmp332.Append("GetInfos: ");
        GetInfos.ToString(tmp332);
      }
      if(__isset.client_protocol_i64)
      {
        if(0 < tmp333++) { tmp332.Append(", "); }
        tmp332.Append("Client_protocol_i64: ");
        Client_protocol_i64.ToString(tmp332);
      }
      if((ConnectionProperties != null) && __isset.connectionProperties)
      {
        if(0 < tmp333++) { tmp332.Append(", "); }
        tmp332.Append("ConnectionProperties: ");
        ConnectionProperties.ToString(tmp332);
      }
      if((InitialNamespace != null) && __isset.initialNamespace)
      {
        if(0 < tmp333++) { tmp332.Append(", "); }
        tmp332.Append("InitialNamespace: ");
        InitialNamespace.ToString(tmp332);
      }
      if(__isset.canUseMultipleCatalogs)
      {
        if(0 < tmp333++) { tmp332.Append(", "); }
        tmp332.Append("CanUseMultipleCatalogs: ");
        CanUseMultipleCatalogs.ToString(tmp332);
      }
      tmp332.Append(')');
      return tmp332.ToString();
    }
  }

}
