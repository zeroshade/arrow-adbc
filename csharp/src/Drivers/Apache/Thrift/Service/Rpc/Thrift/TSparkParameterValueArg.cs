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

  internal partial class TSparkParameterValueArg : TBase
  {
    private string _type;
    private string _value;
    private List<global::Apache.Hive.Service.Rpc.Thrift.TSparkParameterValueArg> _arguments;

    public string Type
    {
      get
      {
        return _type;
      }
      set
      {
        __isset.@type = true;
        this._type = value;
      }
    }

    public string Value
    {
      get
      {
        return _value;
      }
      set
      {
        __isset.@value = true;
        this._value = value;
      }
    }

    public List<global::Apache.Hive.Service.Rpc.Thrift.TSparkParameterValueArg> Arguments
    {
      get
      {
        return _arguments;
      }
      set
      {
        __isset.@arguments = true;
        this._arguments = value;
      }
    }


    public Isset __isset;
    public struct Isset
    {
      public bool @type;
      public bool @value;
      public bool @arguments;
    }

    public TSparkParameterValueArg()
    {
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
              if (field.Type == TType.String)
              {
                Type = await iprot.ReadStringAsync(cancellationToken);
              }
              else
              {
                await TProtocolUtil.SkipAsync(iprot, field.Type, cancellationToken);
              }
              break;
            case 2:
              if (field.Type == TType.String)
              {
                Value = await iprot.ReadStringAsync(cancellationToken);
              }
              else
              {
                await TProtocolUtil.SkipAsync(iprot, field.Type, cancellationToken);
              }
              break;
            case 3:
              if (field.Type == TType.List)
              {
                {
                  var _list409 = await iprot.ReadListBeginAsync(cancellationToken);
                  Arguments = new List<global::Apache.Hive.Service.Rpc.Thrift.TSparkParameterValueArg>(_list409.Count);
                  for(int _i410 = 0; _i410 < _list409.Count; ++_i410)
                  {
                    global::Apache.Hive.Service.Rpc.Thrift.TSparkParameterValueArg _elem411;
                    _elem411 = new global::Apache.Hive.Service.Rpc.Thrift.TSparkParameterValueArg();
                    await _elem411.ReadAsync(iprot, cancellationToken);
                    Arguments.Add(_elem411);
                  }
                  await iprot.ReadListEndAsync(cancellationToken);
                }
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
        var tmp412 = new TStruct("TSparkParameterValueArg");
        await oprot.WriteStructBeginAsync(tmp412, cancellationToken);
        var tmp413 = new TField();
        if((Type != null) && __isset.@type)
        {
          tmp413.Name = "type";
          tmp413.Type = TType.String;
          tmp413.ID = 1;
          await oprot.WriteFieldBeginAsync(tmp413, cancellationToken);
          await oprot.WriteStringAsync(Type, cancellationToken);
          await oprot.WriteFieldEndAsync(cancellationToken);
        }
        if((Value != null) && __isset.@value)
        {
          tmp413.Name = "value";
          tmp413.Type = TType.String;
          tmp413.ID = 2;
          await oprot.WriteFieldBeginAsync(tmp413, cancellationToken);
          await oprot.WriteStringAsync(Value, cancellationToken);
          await oprot.WriteFieldEndAsync(cancellationToken);
        }
        if((Arguments != null) && __isset.@arguments)
        {
          tmp413.Name = "arguments";
          tmp413.Type = TType.List;
          tmp413.ID = 3;
          await oprot.WriteFieldBeginAsync(tmp413, cancellationToken);
          await oprot.WriteListBeginAsync(new TList(TType.Struct, Arguments.Count), cancellationToken);
          foreach (global::Apache.Hive.Service.Rpc.Thrift.TSparkParameterValueArg _iter414 in Arguments)
          {
            await _iter414.WriteAsync(oprot, cancellationToken);
          }
          await oprot.WriteListEndAsync(cancellationToken);
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
      if (!(that is TSparkParameterValueArg other)) return false;
      if (ReferenceEquals(this, other)) return true;
      return ((__isset.@type == other.__isset.@type) && ((!__isset.@type) || (global::System.Object.Equals(Type, other.Type))))
        && ((__isset.@value == other.__isset.@value) && ((!__isset.@value) || (global::System.Object.Equals(Value, other.Value))))
        && ((__isset.@arguments == other.__isset.@arguments) && ((!__isset.@arguments) || (TCollections.Equals(Arguments, other.Arguments))));
    }

    public override int GetHashCode() {
      int hashcode = 157;
      unchecked {
        if((Type != null) && __isset.@type)
        {
          hashcode = (hashcode * 397) + Type.GetHashCode();
        }
        if((Value != null) && __isset.@value)
        {
          hashcode = (hashcode * 397) + Value.GetHashCode();
        }
        if((Arguments != null) && __isset.@arguments)
        {
          hashcode = (hashcode * 397) + TCollections.GetHashCode(Arguments);
        }
      }
      return hashcode;
    }

    public override string ToString()
    {
      var tmp415 = new StringBuilder("TSparkParameterValueArg(");
      int tmp416 = 0;
      if((Type != null) && __isset.@type)
      {
        if(0 < tmp416++) { tmp415.Append(", "); }
        tmp415.Append("Type: ");
        Type.ToString(tmp415);
      }
      if((Value != null) && __isset.@value)
      {
        if(0 < tmp416++) { tmp415.Append(", "); }
        tmp415.Append("Value: ");
        Value.ToString(tmp415);
      }
      if((Arguments != null) && __isset.@arguments)
      {
        if(0 < tmp416++) { tmp415.Append(", "); }
        tmp415.Append("Arguments: ");
        Arguments.ToString(tmp415);
      }
      tmp415.Append(')');
      return tmp415.ToString();
    }
  }

}
