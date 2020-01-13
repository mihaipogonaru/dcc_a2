package net.floodlightcontroller.atds;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPortDesc;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.types.DatapathId;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IListener;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.PortChangeType;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;

public abstract class BasicModule implements IOFMessageListener, IOFSwitchListener, IFloodlightModule
{
	protected IFloodlightProviderService floodlightProvider;
	protected IOFSwitchService switchService;
	protected static Logger logger;

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException
	{
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		switchService = context.getServiceImpl(IOFSwitchService.class);
	    logger = LoggerFactory.getLogger(this.getClass());
	    
	    pseudoConstructor();
	}

	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException
	{
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		floodlightProvider.addOFMessageListener(OFType.ERROR, this);
		
		/* TODO: maybe write code for these as well... when I feel like it >:) */
//		floodlightProvider.addOFMessageListener(OFType.BARRIER_REPLY, this);
//		floodlightProvider.addOFMessageListener(OFType.FEATURES_REPLY, this);
//		floodlightProvider.addOFMessageListener(OFType.STATS_REPLY, this);
//		floodlightProvider.addOFMessageListener(OFType.FLOW_REMOVED, this);
		
		switchService.addOFSwitchListener(this);
		
		logger.info("Module startup: {}", getName());
	}
	
	@Override
	public void switchActivated(DatapathId switchId)
	{
		
	}

	@Override
	public void switchPortChanged(DatapathId switchId, OFPortDesc port, PortChangeType type)
	{
		/* nothing */
	}

	@Override
	public void switchChanged(DatapathId switchId)
	{
		/* nothing */
	}
	
	@Override
	public void switchAdded(DatapathId switchId)
	{
		IOFSwitch sw = switchService.getSwitch(switchId);
		if (sw == null)
			return;
		handleSwitchUp(sw);
	}

	@Override
	public void switchRemoved(DatapathId switchId)
	{
		/* nothing */
	}
	
	@Override
	public void switchDeactivated(DatapathId switchId)
	{
		/* nothing */
	}

	@Override
	public IListener.Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx)
	{
		switch (msg.getType())
		{
		case PACKET_IN:
			receivePacketIn(sw, (OFPacketIn)msg, cntx);
			break;
			
//		case FLOW_REMOVED:
//			receiveFlowRemoved(sw, (OFFlowRemoved)msg, cntx);
//			break;
					
		case ERROR:
			logger.info("Received an error {} from switch {}", msg, sw);
			break;
			
		default:
			break;
		}
		
		return Command.CONTINUE;
	}
	
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies()
	{
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<>();
		
		l.add(IFloodlightProviderService.class);
		return l;
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name)
	{
		return false;
	}
	
	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls()
	{
		return null;
	}
	
	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name)
	{
		return false;
	}
	
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices()
	{
		return null;
	}
	
	@Override
	public String getName()
	{
		return this.getClass().getSimpleName();
	}
	
	/* stuff that must be implemented */
	protected abstract void pseudoConstructor();
	
//	@Override
//	public abstract void switchAdded(DatapathId switchId);
	
//	@Override
//	public abstract void switchRemoved(DatapathId switchId);
	
	protected abstract void receivePacketIn(IOFSwitch sw, OFPacketIn msg, FloodlightContext cntx);
	
//	protected abstract void receiveFlowRemoved(IOFSwitch sw, OFFlowRemoved msg, FloodlightContext cntx);
	
	protected abstract void handleSwitchUp(IOFSwitch sw);
	
}
