package dcc_a2;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.projectfloodlight.openflow.protocol.OFBarrierRequest;
import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TransportPort;

import net.floodlightcontroller.atds.BasicModule;
import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;

class TCPConnection {
	enum Type {
		Normal,
		MasterFlow,
		JoinedFlow;
	}
	
	enum Status {
		SYNED,
		ACKED;
	}
	
	private Type type;
	private Status status;
	public OFPort eport;
	
	public TCPConnection(Type type, OFPort eport) {
		this.type = type;
		this.status = Status.SYNED;
		this.eport = eport;
	}
	
	public boolean isTCP() {
		return this.type == Type.Normal;
	}
	
	public boolean isMPTCPMaster() {
		return this.type == Type.MasterFlow;
	}
	
	public boolean isMPTCPJoined() {
		return this.type == Type.JoinedFlow;
	}
	
	public void reset() {
		this.status = Status.SYNED;
	}
	
	public void establish() {
		this.status = Status.ACKED;
	}
	
	public boolean isNew() {
		return this.status == Status.SYNED;
	}
	
	public boolean isEstablished() {
		return this.status == Status.ACKED;
	}
}

class GenericOption {
	public int type;
	public int length;
	
	public static final int OPT_END = 0x0;
	public static final int OPT_NOOP = 0x1;
	
	public GenericOption(byte[] content) {
		this.type = Byte.toUnsignedInt(ByteBuffer.wrap(content, 0, 1).get());
		
		if (this.type == OPT_END || this.type == OPT_NOOP) {
			this.length = 1;
		} else {
			this.length = Byte.toUnsignedInt(ByteBuffer.wrap(content, 1, 2).get());
		}
	}
}

class MPTCPOption {	
	enum SubType {
		MP_CAPABLE,
		MP_JOIN,
		MP_OTHER;
		
		public static final int MP_CAPABLE_VAL = 0x00;
		public static final int MP_JOIN_VAL = 0x01;
	}
	
	public static final int MPTCP_VAL = 0x001E;
	public int length;
	public SubType subtype;
	public byte[] content;
	
	public MPTCPOption(byte[] content) {
		this.length = Byte.toUnsignedInt(ByteBuffer.wrap(content, 1, 2).get());
		
		ByteBuffer subtypebuf = ByteBuffer.wrap(content, 2, 3);
		int subtype = (Byte.toUnsignedInt(subtypebuf.get()) & 0xF0) >> 4;
		
		if (subtype == SubType.MP_CAPABLE_VAL) {
			this.subtype = SubType.MP_CAPABLE;
		} else if (subtype == SubType.MP_JOIN_VAL) {
			this.subtype = SubType.MP_JOIN;
		} else {
			this.subtype = SubType.MP_OTHER;
		}
		
		this.content = Arrays.copyOfRange(content, 4, this.length);
	}
	
	public static MPTCPOption searchForMPTCP(byte[] content) {
		int idx = 0;
		
		if (content == null)
			return null;
		
		while (idx < content.length) {
			byte[] crr = Arrays.copyOfRange(content, idx, content.length);
			GenericOption opt = new GenericOption(crr);
			
			if (opt.type == GenericOption.OPT_END)
				return null;
			
			if (opt.type == MPTCP_VAL) {
				MPTCPOption mptcp = new MPTCPOption(crr);
				
				if (mptcp.subtype == SubType.MP_CAPABLE || mptcp.subtype == SubType.MP_JOIN)
					return mptcp;
			}
			
			idx += opt.length;
		}
		
		return null;
	}
	
	private static byte[] getHash(byte[] content) {
		MessageDigest md = null;
	    try {
	        md = MessageDigest.getInstance("SHA-1");
	    }
	    catch(NoSuchAlgorithmException e) {
	        e.printStackTrace();
	    }
	    
	    return md.digest(content);
	}
	
	public static byte[] getRecvKeyHash(MPTCPOption mptcp) {
		if (mptcp.subtype != SubType.MP_CAPABLE || mptcp.length != 20)
			return null;
		
		byte[] recvKey = Arrays.copyOfRange(mptcp.content, 8, mptcp.content.length);
		byte[] token = Arrays.copyOfRange(getHash(recvKey), 0, 4);
		
		return token;
	}
	
	public static byte[] getToken(MPTCPOption mptcp) {
		if (mptcp.subtype != SubType.MP_JOIN || mptcp.length != 12)
			return null;
		
		return Arrays.copyOfRange(mptcp.content, 0, 4);
	}
}

public class Controller extends BasicModule {
	enum Host {
		C,
		S1,
		S2;
	}
	
	enum TCPFlags {
		SYN(2),
		ACK(16);
		
		private int value;		
		private TCPFlags(int value) 
	    { 
	        this.value = value; 
	    } 
		
		public int Value() {
			return this.value;
		}
		
		static boolean isSyn(short flags) {
			return ((flags & SYN.Value()) != 0 &&
					(flags & ACK.Value()) == 0);
		}
		
		static boolean isSynAck(short flags) {
			return ((flags & SYN.Value()) != 0 &&
					(flags & ACK.Value()) != 0);
		}
		
		static boolean isAck(short flags) {
			return ((flags & SYN.Value()) == 0 &&
					(flags & ACK.Value()) != 0);
		}
	}
	
	final Map<Host, OFPort> host_port = Map.of(
			Host.C, OFPort.of(1),
			Host.S1, OFPort.of(2),
			Host.S2, OFPort.of(3));
	
	final Map<Integer, Host> port_host = Map.of(
			1, Host.C,
			2, Host.S1,
			3, Host.S2);
	
	ConcurrentHashMap<MacAddress, OFPort> macTable;
	ConcurrentHashMap<Integer, String> tokenToId;
	ConcurrentHashMap<String, TCPConnection> idToConn;
	
	@Override
	protected void pseudoConstructor() {
		// TODO Auto-generated method stub
		macTable = new ConcurrentHashMap<MacAddress, OFPort>();
		tokenToId = new ConcurrentHashMap<Integer, String>();
		idToConn = new ConcurrentHashMap<String, TCPConnection>();
	}
	
	private static List<OFAction> getOutputAction(IOFSwitch sw, OFPort eport) {
		OFAction action = sw.getOFFactory().actions().buildOutput().setPort(eport).setMaxLen(0xffFFffFF).build();
		List<OFAction> actions = new ArrayList<>(1);
		actions.add(action);
		
		return actions;
	}
	
	private static void injectPacket(IOFSwitch sw, OFPort eport, OFPacketOut.Builder pob) {	
		logger.info("Sending to port " + eport);
		pob.setActions(getOutputAction(sw, eport));		
		sw.write(pob.build());
	}
	
	private static Integer fromByteArray(byte[] bytes) {
		return ByteBuffer.wrap(bytes).getInt();
	}
	
	private static void addFlowOutput(IOFSwitch sw, MacAddress scrEth, MacAddress dstEth,
			IPv4Address srcIp, IPv4Address dstIp, TransportPort srcPort, TransportPort dstPort, OFPort eport) {
	
		Match.Builder mb = sw.getOFFactory().buildMatch();
		
		mb.setExact(MatchField.ETH_SRC, scrEth)
		    .setExact(MatchField.ETH_DST, dstEth)
			.setExact(MatchField.ETH_TYPE, EthType.IPv4)
			.setExact(MatchField.IPV4_SRC, srcIp)
			.setExact(MatchField.IPV4_DST, dstIp)
			.setExact(MatchField.IP_PROTO, IpProtocol.TCP)
			.setExact(MatchField.TCP_SRC, srcPort)
			.setExact(MatchField.TCP_DST, dstPort);

		int idleTimeout = 200; /* 0 means no timeout */
		int hardTimeout = 0; /* 0 means no timeout */
		Match match = mb.build();
		
		OFFlowMod.Builder fmb = sw.getOFFactory().buildFlowAdd();
		fmb.setMatch(match);

		fmb.setIdleTimeout(idleTimeout);
		fmb.setHardTimeout(hardTimeout);

		fmb.setActions(getOutputAction(sw, eport));
		sw.write(fmb.build());
	}
	
	@Override
	protected void receivePacketIn(IOFSwitch sw, OFPacketIn msg, FloodlightContext cntx) {
		// TODO Auto-generated method stub
		logger.info("New packet! I gotta do something with it...");
		
		/* get the ingress port */
		OFPort iport = msg.getVersion().compareTo(OFVersion.OF_12) < 0 ? msg.getInPort() : msg.getMatch().get(MatchField.IN_PORT);
		
		/* get the buffer ID */
		OFBufferId bufferID = msg.getBufferId();
		
		/* get the payload */
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		MacAddress srcEth = eth.getSourceMACAddress();
		MacAddress dstEth = eth.getDestinationMACAddress();
		
		if (srcEth.isBroadcast()) {
			logger.info("Broadcast source. Dropping");
			return;
		}
		
		logger.info("Source port " + iport);
		logger.info("Source " + srcEth);
		logger.info("Dest " + dstEth);
		
		/* Start building the packet out */
		OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
		pob.setBufferId(bufferID);
		pob.setInPort(iport);
		
		if (pob.getBufferId() == OFBufferId.NO_BUFFER)
			pob.setData(eth.serialize());
		
		/* Check ARP */
		if (eth.getEtherType() == EthType.ARP)
			logger.info("ARP Packet");

		/* Save incoming MAC */
		macTable.put(eth.getSourceMACAddress(), iport);
		
		/* Get port for destination from CAM table */
		OFPort eport = OFPort.FLOOD;
		
		if (macTable.containsKey(dstEth))
			eport = macTable.get(dstEth);
		logger.info("CAM entry: " + eport);
		
		/* Balancer logic */
		if (port_host.containsKey(iport.getPortNumber()) == false) {
			logger.info("Unknown ingress port. Sending to CAM eport");
			injectPacket(sw, eport, pob);
			return;
		}
		
		Host ihost = port_host.get(iport.getPortNumber());
		logger.info("Source Host " + ihost);

		/* We only check the SYN packet sent by the client and the ACK that
		 * follows the SYN-ACK. SYN packets also reset our connection status
		 * 
		 * There are a lot of cases that we do not handle (wrong SYN, packet drops, retransmissions etc.)
		 */
		if (ihost != Host.C) {
			logger.info("Source Host is not the client. Sending to CAM eport");
			injectPacket(sw, eport, pob);
			return;
		}
		
		/* Check the ethertype of the Ethernet frame */
        if (eth.getEtherType() == EthType.IPv4) {
            /* We got an IPv4 packet; get the payload from Ethernet */
            IPv4 ipv4 = (IPv4) eth.getPayload();
             
            /*Get IPv4 addresses */
            IPv4Address srcIp = ipv4.getSourceAddress();
            IPv4Address dstIp = ipv4.getDestinationAddress();
             
            /* Check the IP protocol version of the IPv4 packet's payload */
            if (ipv4.getProtocol() == IpProtocol.TCP) {
                /* We got a TCP packet; get the payload from IPv4 */
                TCP tcp = (TCP) ipv4.getPayload();
  
                /* Get TCP ports, flags and options */
                TransportPort srcPort = tcp.getSourcePort();
                TransportPort dstPort = tcp.getDestinationPort();
                short flags = tcp.getFlags();
                
                logger.info("IP: " + srcIp + " -> " + dstIp);
                logger.info("Port: " + srcPort + " -> " + dstPort);
                logger.info("Flags " + flags);

        		String idConn = srcIp + "_" + dstIp + "_" + srcPort + "_" + dstPort;
        		int hashConn = (int) ((Integer.toUnsignedLong(idConn.hashCode())) % 2);
        		Host ehost = port_host.get(hashConn + 2);
        		
        		logger.info("Hashed to host " + ehost + " - " + hashConn);
        		
        		eport = host_port.get(ehost);
        		if (TCPFlags.isSyn(flags)) {
        			/* SYN creates/rewrites a connection
        			 * We must check the MP_CAPABLE/MP_JOIN option
        			 */
        			logger.info("SYN Packet. Checking for MPTCP");
        			
        			TCPConnection conn = null;
        			MPTCPOption mptcp = MPTCPOption.searchForMPTCP(tcp.getOptions());
        			
        			if (mptcp != null) {
        				if (mptcp.subtype == MPTCPOption.SubType.MP_CAPABLE) {
        					conn = new TCPConnection(TCPConnection.Type.MasterFlow, eport);
        					logger.info("MPTCP_CAPABLE found. Created a connection");
        				} else if (mptcp.subtype == MPTCPOption.SubType.MP_JOIN) {
        					byte[] recvKeyHash = MPTCPOption.getToken(mptcp);
        					
        					if (recvKeyHash != null) {
	        					Integer token = fromByteArray(recvKeyHash);        					
	        					String masterConnId = tokenToId.get(token);
	        					
	        					if (masterConnId != null) {
		        					TCPConnection masterConn = idToConn.get(masterConnId);
	        						eport = masterConn.eport;
	        								
		        					conn = new TCPConnection(TCPConnection.Type.JoinedFlow, eport);
		        					logger.info("Correct MPTCP_JOIN. Connection found for token: " + token + ". Eport: " + eport);
	        					} else {
	        						logger.info("Incorrect MPTCP_JOIN. No connection found for token: " + token);
	        					}
        					}
        				}
        			}

        			if (conn == null) {
        				conn = new TCPConnection(TCPConnection.Type.Normal, eport);
        				logger.info("Treating this as a normal TCP connection");
        			}
        			
        			idToConn.put(idConn, conn);
        			
        		} else if (TCPFlags.isAck(flags)) {
        			/* 
        			 * ACK should only get to us if we are starting a connection that
        			 * a.k.a this should be the ack after syn
        			 * 
        			 * We must check the MP_CAPABLE/MP_JOIN option
        			 */
        			logger.info("ACK Packet. Checking for MPTCP");
        			
        			TCPConnection conn = idToConn.get(idConn);
        			boolean addFlowRules = true;
        			
        			if (conn == null) {
        				logger.info("Connection not found. Sending to CAM eport");
        				injectPacket(sw, eport, pob);
        	            return;
        			}
        			
        			logger.info("Found connection to port " + eport);
        			if (conn.isEstablished())
        				logger.info("Connection already established. The rules might have expired");
        			
        			MPTCPOption mptcp = MPTCPOption.searchForMPTCP(tcp.getOptions());
        			if (mptcp != null) {
        				if (mptcp.subtype == MPTCPOption.SubType.MP_CAPABLE) {
        					logger.info("MPTCP_CAPABLE found");
        					
        					/* Token obtained from receiver's key */
        					byte[] recvKeyHash = MPTCPOption.getRecvKeyHash(mptcp);
        					if (recvKeyHash != null) {
        						Integer token = fromByteArray(recvKeyHash);
        						
        						tokenToId.put(token, idConn);
        						logger.info("Set token " + token + " to this connection");
        					} else {
        						logger.info("No recv key found");
        						addFlowRules = false;
        					}
        				} else if (mptcp.subtype == MPTCPOption.SubType.MP_JOIN) {
        					logger.info("MPTCP_JOIN found. Checking that connection was initiated by MP_JOIN");
        					
        					/* The connection must be of joined type, or the ACK is wrong */
        					addFlowRules = conn.isMPTCPJoined();
        				}
        			}
        			
        			if (addFlowRules) {
	    				logger.info("Adding flow rules");
						addFlowOutput(sw, srcEth, dstEth, srcIp, dstIp, srcPort, dstPort, eport);
						addFlowOutput(sw, dstEth, srcEth, dstIp, srcIp, dstPort, srcPort, iport);
						
						/* Barrier so we don't receive any more ACK's */
						OFBarrierRequest.Builder brb = sw.getOFFactory().buildBarrierRequest();
						sw.write(brb.build());
        			} else {
        				logger.info("ACK was not ok. We don't add flow rules");
        			}
        		}
        		
        		logger.info("Packet type handled");
        		injectPacket(sw, eport, pob);
        		return;
            }
        }
		
        logger.info("Packet type not handled. Sending to CAM eport");
        injectPacket(sw, eport, pob);
	}

	@Override
	protected void handleSwitchUp(IOFSwitch sw) {
		// TODO Auto-generated method stub
		// We only have one switch
	}
}
