"""
Path Explorer Module
Advanced symbolic execution path exploration for ECU binaries.
"""

import logging
from typing import List, Dict, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# Try to import angr
try:
    import angr
    import claripy
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False
    angr = None
    claripy = None


@dataclass
class CodeRegion:
    """Represents a region of code in the binary."""
    start_addr: int
    end_addr: int
    size: int
    name: Optional[str] = None
    is_reachable: bool = True


@dataclass
class PathInfo:
    """Information about an execution path."""
    path_id: int
    length: int
    addresses: List[int]
    constraints: List[str]
    input_bytes: Optional[bytes] = None
    ends_at: Optional[int] = None
    is_complete: bool = False


@dataclass
class PathResults:
    """Results from path exploration."""
    paths_explored: int
    unique_blocks_reached: int
    coverage_percentage: float
    dead_code_regions: List[CodeRegion]
    loop_bounds: Dict[int, int]
    interesting_paths: List[PathInfo]
    exploration_time: float = 0.0
    notes: List[str] = field(default_factory=list)


class PathExplorer:
    """
    Advanced path exploration using symbolic execution.
    
    Features:
    - Full state space exploration with constraints
    - Loop detection and bounding
    - Dead code identification
    - Path constraint solving for exploit generation
    - Coverage analysis
    """
    
    def __init__(self, binary_path: str, use_simulation: bool = False):
        """
        Initialize path explorer.
        
        Args:
            binary_path: Path to binary to analyze
            use_simulation: Force simulation mode
        """
        self.binary_path = binary_path
        self.use_simulation = use_simulation or not ANGR_AVAILABLE
        self.project = None
        self.cfg = None
        
        # Exploration state
        self.visited_blocks: Set[int] = set()
        self.loop_headers: Dict[int, int] = {}  # addr -> iteration count
        
    def initialize(self) -> bool:
        """Initialize angr project."""
        
        if self.use_simulation:
            logger.info("[Simulation] Path explorer initialized")
            return True
        
        try:
            self.project = angr.Project(
                self.binary_path,
                auto_load_libs=False
            )
            
            logger.info(f"Path explorer initialized for {self.binary_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize path explorer: {e}")
            return False
    
    def explore_all_paths(
        self,
        max_paths: int = 1000,
        max_depth: int = 100,
        timeout: int = 300
    ) -> PathResults:
        """
        Explore all reachable paths in the binary.
        
        Args:
            max_paths: Maximum number of paths to explore
            max_depth: Maximum depth per path
            timeout: Exploration timeout in seconds
            
        Returns:
            PathResults with exploration data
        """
        import time
        start_time = time.time()
        
        if self.use_simulation:
            return self._simulate_exploration()
        
        if not self.project:
            if not self.initialize():
                return PathResults(
                    paths_explored=0,
                    unique_blocks_reached=0,
                    coverage_percentage=0.0,
                    dead_code_regions=[],
                    loop_bounds={},
                    interesting_paths=[],
                    notes=['Failed to initialize project']
                )
        
        try:
            # Build CFG first
            logger.info("Building CFG for path exploration...")
            self.cfg = self.project.analyses.CFGFast()
            total_blocks = len(self.cfg.graph.nodes())
            
            # Create initial state
            state = self.project.factory.entry_state()
            simgr = self.project.factory.simulation_manager(state)
            
            paths_found: List[PathInfo] = []
            self.visited_blocks = set()
            
            # Exploration loop
            path_count = 0
            while simgr.active and path_count < max_paths:
                if time.time() - start_time > timeout:
                    logger.warning("Exploration timeout reached")
                    break
                
                # Step forward
                simgr.step()
                
                # Track visited blocks
                for active_state in simgr.active:
                    self.visited_blocks.add(active_state.addr)
                    
                    # Detect loops
                    self._update_loop_detection(active_state)
                
                # Process completed/deadended paths
                for state in simgr.deadended:
                    path_info = self._extract_path_info(state, path_count)
                    paths_found.append(path_info)
                    path_count += 1
                
                simgr.drop(stash='deadended')
            
            # Calculate coverage
            coverage = (len(self.visited_blocks) / total_blocks * 100) if total_blocks > 0 else 0
            
            # Find dead code
            dead_code = self._find_dead_code()
            
            elapsed = time.time() - start_time
            
            return PathResults(
                paths_explored=path_count,
                unique_blocks_reached=len(self.visited_blocks),
                coverage_percentage=coverage,
                dead_code_regions=dead_code,
                loop_bounds=self.loop_headers.copy(),
                interesting_paths=paths_found[:10],  # Top 10
                exploration_time=elapsed
            )
            
        except Exception as e:
            logger.error(f"Path exploration failed: {e}")
            return PathResults(
                paths_explored=0,
                unique_blocks_reached=0,
                coverage_percentage=0.0,
                dead_code_regions=[],
                loop_bounds={},
                interesting_paths=[],
                notes=[f'Exploration error: {e}']
            )
    
    def find_path_to_target(
        self,
        target_addr: int,
        max_steps: int = 10000
    ) -> Optional[bytes]:
        """
        Find input that reaches a specific address.
        
        Args:
            target_addr: Target address to reach
            max_steps: Maximum exploration steps
            
        Returns:
            Input bytes that reach target, or None
        """
        if self.use_simulation:
            logger.info(f"[Simulation] Would find path to {hex(target_addr)}")
            return None
        
        if not self.project:
            if not self.initialize():
                return None
        
        try:
            # Create state with symbolic stdin
            state = self.project.factory.entry_state()
            
            # Symbolic input
            input_size = 256
            symbolic_input = claripy.BVS('target_input', 8 * input_size)
            state.posix.stdin.write_to(symbolic_input)
            state.posix.stdin.seek(0)
            
            simgr = self.project.factory.simulation_manager(state)
            
            # Explore toward target
            simgr.explore(find=target_addr, n=max_steps)
            
            if simgr.found:
                found_state = simgr.found[0]
                
                # Concretize input
                try:
                    concrete_input = found_state.solver.eval(
                        symbolic_input,
                        cast_to=bytes
                    )
                    return concrete_input
                except Exception as e:
                    logger.warning(f"Could not concretize input: {e}")
                    return None
            
            return None
            
        except Exception as e:
            logger.error(f"Path finding failed: {e}")
            return None
    
    def detect_dead_code(self) -> List[CodeRegion]:
        """
        Find unreachable code regions.
        
        Returns:
            List of dead code regions
        """
        if self.use_simulation:
            return []
        
        if not self.cfg:
            if not self.project:
                self.initialize()
            if self.project:
                self.cfg = self.project.analyses.CFGFast()
        
        return self._find_dead_code()
    
    def _find_dead_code(self) -> List[CodeRegion]:
        """Internal method to identify unreachable code."""
        
        if not self.cfg:
            return []
        
        dead_regions = []
        
        # Get all function blocks
        for func in self.cfg.functions.values():
            if func.is_simprocedure:
                continue
            
            # Check if function is reachable from entry
            func_addr = func.addr
            
            # Simple check: if we have exploration data, check visited
            if self.visited_blocks and func_addr not in self.visited_blocks:
                # Check if any block in function was visited
                func_visited = False
                for block_addr in self._get_function_blocks(func):
                    if block_addr in self.visited_blocks:
                        func_visited = True
                        break
                
                if not func_visited:
                    dead_regions.append(CodeRegion(
                        start_addr=func_addr,
                        end_addr=func_addr + func.size,
                        size=func.size,
                        name=func.name,
                        is_reachable=False
                    ))
        
        return dead_regions
    
    def _get_function_blocks(self, func) -> Set[int]:
        """Get all block addresses in a function."""
        blocks = set()
        try:
            for block in func.blocks:
                blocks.add(block.addr)
        except Exception:
            pass
        return blocks
    
    def _update_loop_detection(self, state) -> None:
        """Track loop iterations."""
        addr = state.addr
        
        # Check if we're at a known loop header
        if addr in self.loop_headers:
            self.loop_headers[addr] += 1
        else:
            # Check if this looks like a loop (visited before)
            if hasattr(state, 'history'):
                history_addrs = [h.addr for h in state.history.lineage if hasattr(h, 'addr')]
                if addr in history_addrs:
                    self.loop_headers[addr] = 1
    
    def _extract_path_info(self, state, path_id: int) -> PathInfo:
        """Extract information about an execution path."""
        
        addresses = []
        constraints = []
        
        try:
            # Get address history
            if hasattr(state, 'history'):
                for h in state.history.lineage:
                    if hasattr(h, 'addr'):
                        addresses.append(h.addr)
            
            # Get path constraints
            if hasattr(state, 'solver'):
                for constraint in state.solver.constraints[:10]:
                    try:
                        constraints.append(str(constraint)[:100])
                    except Exception:
                        pass
                        
        except Exception as e:
            logger.debug(f"Error extracting path info: {e}")
        
        return PathInfo(
            path_id=path_id,
            length=len(addresses),
            addresses=addresses[-20:],  # Last 20 addresses
            constraints=constraints,
            ends_at=state.addr if hasattr(state, 'addr') else None,
            is_complete=True
        )
    
    def _simulate_exploration(self) -> PathResults:
        """Simulate path exploration for testing."""
        
        # Read binary to get size estimate
        try:
            size = Path(self.binary_path).stat().st_size
            estimated_blocks = size // 16  # Rough estimate
            
            return PathResults(
                paths_explored=0,
                unique_blocks_reached=0,
                coverage_percentage=0.0,
                dead_code_regions=[],
                loop_bounds={},
                interesting_paths=[],
                notes=[
                    'Simulation mode - install angr for real path exploration',
                    f'Estimated ~{estimated_blocks} basic blocks'
                ]
            )
        except Exception as e:
            return PathResults(
                paths_explored=0,
                unique_blocks_reached=0,
                coverage_percentage=0.0,
                dead_code_regions=[],
                loop_bounds={},
                interesting_paths=[],
                notes=[f'Simulation error: {e}']
            )
    
    def get_call_graph(self) -> Dict[str, List[str]]:
        """
        Get function call graph.
        
        Returns:
            Dict mapping function names to list of called functions
        """
        if self.use_simulation or not self.cfg:
            return {}
        
        call_graph = {}
        
        try:
            for func in self.cfg.functions.values():
                callees = []
                
                try:
                    for block in func.blocks:
                        for insn in block.capstone.insns:
                            if insn.mnemonic in ['call', 'bl', 'blr']:
                                # Get call target
                                if insn.operands:
                                    target = insn.operands[0].imm
                                    if target in self.cfg.functions:
                                        callee_name = self.cfg.functions[target].name
                                        callees.append(callee_name)
                except Exception:
                    pass
                
                if callees:
                    call_graph[func.name] = list(set(callees))
                    
        except Exception as e:
            logger.error(f"Error building call graph: {e}")
        
        return call_graph
