package net.deterlab.abac;

import org.apache.commons.collections15.*;

import edu.uci.ics.jung.graph.*;
import edu.uci.ics.jung.graph.util.*;

import java.util.*;

/**
 * A class for making queries against the graph. It supports direct queries as
 * well as reachability in either direction. See the run method for details.
 * @author <a href="http://abac.deterlab.net">ISI ABAC team</a>
 * @version 1.5
 */
class Query {
    /** Internal graph representation */
    private Graph<Role,Credential> g;
    /** Count of vertices in the most recent calculate path */
    private boolean valid;

    /**
     * Create a query to be run against the credential graph.
     * @param g a Graph represneting the credentials and implicit connections.
     */
    public Query(Graph<Role,Credential> g) {
        this.g = g;
	valid = false;
    }

    /**
     * Run a query against the graph, returning a graph of the results. If the
     * results are empty or the query fails, an empty graph is returned. When
     * derived edges are involved, the subgraphs that imply those edges are
     * included.
     * @param attr a String containing the role to look for
     * @param prin a String containing the principal
     * @return a Graph with the proof or partial proof.
     */
    public Graph<Role,Credential> run(String attr, String prin) {
	Role attribute = (!attr.isEmpty()) ? new Role(attr) : null;
	Role principal = (!prin.isEmpty()) ? new Role(prin) : null;
        Graph<Role,Credential> ret =
            Graphs.<Role,Credential>synchronizedDirectedGraph(
                    new DirectedSparseGraph<Role,Credential>());
	ArrayList<Graph<Role, Credential> > subs = 
	    new ArrayList<Graph<Role, Credential> >();
	Set<Role> hasAttr = null;

	// System.out.println("In run " + attr + " " + prin);

	if (attribute == null && principal == null ) {
	    valid = false;
	    return ret;
	}
	else if (principal != null ) {
	    /* This branch happens if attribute is null or not, and either is
	     * fine for the bfs routine. */
	    valid = bfs(principal, attribute, ret, 
		    new forwardSearch<Role, Credential>());
	} else {
	    /* attribute is != null here */
	    valid = bfs(attribute, principal, ret, 
		    new reverseSearch<Role, Credential>());
	} 

	if ( principal == null ) hasAttr = find_principals(attribute);
	else {
	    hasAttr =new HashSet<Role>();
	    hasAttr.add(principal);
	}

	/* Now ret contains the primary path of the proof, for each linking
	 * role or intersection on that path, we construct a Query object to
	 * make that subproof. */
	for (Credential c: ret.getEdges() ) {
	    Role head = c.head();
	    Role tail = c.tail();

	    if ( head.is_linking()) {
		Query subq = new Query(g);
		subs.add(subq.run(head.linked_role(), tail.principal()));
		if ( !subq.successful()) 
		    throw new RuntimeException("Cannot prove sub-proof: " + 
			    head.linked_role() + " <- " + tail.principal() +
			    " something is very wrong!");
	    } else if ( head.is_intersection() ) {
		try {
		    for (Role r: head.prereqs()) {
			for (Role p : hasAttr) {
			    Query subq = new Query(g);
			    subs.add(subq.run(r.toString(), p.toString()));
			    if ( !subq.successful()) 
				throw new RuntimeException(
					"Cannot prove sub-proof: " + 
					r.toString() + " <- " +  p + 
					" something is very wrong!");
			}
		    }
		}
		catch (ABACException ignored) { }
	    }
	}
	/* Now subs has all the subsidiary proofs in it, merge 'em */
	for (Graph<Role, Credential> sg: subs) {
	    for (Role r: sg.getVertices()) 
		if (!ret.containsVertex(r))
		    ret.addVertex(r);
	    for (Credential c: sg.getEdges() )
		if ( !ret.containsEdge(c)) 
		    ret.addEdge(c, c.head(), c.tail());
	}
        return ret;
    }



    /**
     * Returns true after running a query that returns a non-empty set of
     * vertices.
     * @return a boolean, true after running a query that returns a non-empty
     * set of vertices.
     */
    public boolean successful() {
        return valid;
    }

    /**
     * Returns a collection of principals reachable from a Role when
     * traversing edges in the reverse direction.
     * @param n the Role to start from
     * @return a Set containinf the principals
     */
    public Set<Role> find_principals(Role n) {
        Set<Role> principals = new HashSet<Role>();
	bfs(n, null, null, new principalSearch<Role,Credential>(principals));
        return principals;
    }

    /**
     * Class extended to specialize the behavior of the bfs routine at the core
     * of the query system.  There are two ways to customize - the traversal
     * order which controls if edges are followed in the orientation of the
     * graph or in the reverse orientation and a member called when an edge is
     * added to an output graph.
     */
    private abstract class bfsSearchDirection<V,E> {
	/**
	 * Return a collection of outgoing edges under the search direction's
	 * interpretation.
	 * @param g the Graph&lt;V, E&gt; being traversed
	 * @param v a V, the vertex from which the edges come
	 * @return a collection of outgoing edges under the search direction's
	 * interpretation.
	 */
	public abstract Collection<E> forwardEdges(Graph<V, E> g, V v);
	/**
	 * Return a collection of incoming edges under the search direction's
	 * interpretation.
	 * @param g the Graph&lt;V, E&gt; being traversed
	 * @param v a V, the vertex into which the edges come
	 * @return a collection of outgoing edges under the search direction's
	 * interpretation.
	 */
	public abstract Collection<E> backwardEdges(Graph<V, E> g, V v);
	/**
	 * Return the source of this edge under the search direction's
	 * interpretation.
	 * @param g the Graph&lt;V, E&gt; being traversed
	 * @param e an E, the edge being considered
	 * @return the source of this edge under the search direction's
	 * interpretation.
	 **/
	public abstract V getSource(Graph<V, E> g, E e);
	/**
	 * Return the destination of this edge under the search direction's
	 * interpretation.
	 * @param g the Graph&lt;V, E&gt; being traversed
	 * @param e an E, the edge being considered
	 * @return the destination of this edge under the search direction's
	 * interpretation.
	 **/
	public abstract V getDest(Graph<V, E> g, E e);
	/**
	 * Called when an edge is added; do nothing.
	 * @param e an E edge being added.
	 */
	public void keptEdge(E e) { }
    }

    /**
     * Class that runs the BFS along the graph as defined.
     */
    private class forwardSearch<V,E> extends bfsSearchDirection<V,E> {
	/**
	 * Return a collection of outgoing edges; outgoing is defined by the
	 * graph.
	 * @param g the Graph&lt;V, E&gt; being traversed
	 * @param v a V, the vertex from which the edges come
	 * @return a collection of outgoing edges
	 */
	public Collection<E> forwardEdges(Graph<V, E> g, V v) {
	    return g.getOutEdges(v);
	}
	/**
	 * Return a collection of incoming edges; incoming is defined by the
	 * graph.
	 * @param g the Graph&lt;V, E&gt; being traversed
	 * @param v a V, the vertex into which the edges come
	 * @return a collection of outgoing edges
	 */
	public Collection<E> backwardEdges(Graph<V, E> g, V v) {
	    return g.getInEdges(v);
	}
	/**
	 * Return the source of this edge as defined by the underlying graph.
	 * @param g the Graph&lt;V, E&gt; being traversed
	 * @param e an E, the edge being considered
	 * @return the source of this edge 
	 */
	public V getSource(Graph<V, E> g, E e) {
	    return g.getSource(e);
	}
	/**
	 * Return the destination of this edge as defined by the underlying
	 * graph.
	 * @param g the Graph&lt;V, E&gt; being traversed
	 * @param e an E, the edge being considered
	 * @return the destination of this edge 
	 */
	public V getDest(Graph<V, E> g, E e) {
	    return g.getDest(e);
	}
	/**
	 * Called when an edge is added; do nothing.
	 * @param e an E edge being added.
	 */
	public void keptEdge(E e) { }
    }

    /**
     * Class that runs the BFS along reversed links.
     */
    private class reverseSearch<V,E> extends bfsSearchDirection<V,E> {
	/**
	 * Return a collection of outgoing edges; outgoing is reversed with
	 * respect to the graph.
	 * @param g the Graph&lt;V, E&gt; being traversed
	 * @param v a V, the vertex from which the edges come
	 * @return a collection of outgoing edges
	 */
	public Collection<E> forwardEdges(Graph<V, E> g, V v) {
	    return g.getInEdges(v);
	}
	/**
	 * Return a collection of incoming edges; incoming is reversed with
	 * respect to the graph.
	 * @param g the Graph&lt;V, E&gt; being traversed
	 * @param v a V, the vertex into which the edges come
	 * @return a collection of outgoing edges
	 */
	public Collection<E> backwardEdges(Graph<V, E> g, V v) {
	    return g.getOutEdges(v);
	}
	/**
	 * Return the source of this edge in the reverse of the underlying
	 * graph.
	 * @param g the Graph&lt;V, E&gt; being traversed
	 * @param e an E, the edge being considered
	 * @return the source of this edge 
	 */
	public V getSource(Graph<V, E> g, E e) {
	    return g.getDest(e);
	}
	/**
	 * Return the destination of this edge in the reverse of the underlying
	 * graph.
	 * @param g the Graph&lt;V, E&gt; being traversed
	 * @param e an E, the edge being considered
	 * @return the destination of this edge 
	 */
	public V getDest(Graph<V, E> g, E e) {
	    return g.getSource(e);
	}
    }

    /**
     * Class that traverses the graph in reverse asd collects all principal
     * nodes found.
     */
    private class principalSearch<V, E> 
	    extends reverseSearch<V, E> {
	/** This collects the principals */
	private Set<Role> p;
	/**
	 * Create a principalSearch that inserts into s
	 * @param s a Set of Roles to update (may be null).
	 */
	public principalSearch(Set<Role> s) { 
	    if ( (p = s) == null ) p = new HashSet<Role>();
	}
	/**
	 * Put principals on valid edges into the attached set.
	 * @param e an E (edge) being inserted into the final proof graph
	 */
	public void keptEdge(E e) {
	    if ( !(e instanceof Credential) ) return;

	    Credential c = (Credential) e;
	    if (c.tail().is_principal()) p.add(c.tail());
	}
    }

    /**
     * Conduct a breadth first search along the underlying graph from src to
     * dest.  If a valid path is found, add it to path (which mat be null).
     * The dir parameter controls the direction of the traversal and may invoke
     * a side effect when an edge is added to path.  Though the graph may be
     * traversed in either direction, path is always in the same sense as the
     * underlying graph.  If dest is null the bfs runs until all
     * reachable nodes have been visited and that graph is returned as a
     * success. 
     * @param src the Role to start the search from 
     * @param dest the Role to find a path to
     * @param path a Graph&lt;Role, Credential&gt; in which the result path is
     * returned
     * @param dir a bfsSearchDirection&lt;Role, Credential&gt; that defines direction
     * of search and side effects
     * @return true if the path is found
     */
    private boolean bfs(Role src, Role dest, 
	    Graph<Role, Credential> path, 
	    bfsSearchDirection<Role, Credential> dir) {
	Queue<Role> q = new ArrayDeque<Role>();
	DirectedGraph<Role, Credential> bfs = 
	    new DirectedSparseGraph<Role, Credential>();
	HashSet<Role> visited = new HashSet<Role>();
	boolean foundDest = false;

	if (src == null || !g.containsVertex(src))
	    return false;

	q.add(src);
	visited.add(src);
	bfs.addVertex(src);

	while ( q.size() > 0 && !foundDest) {
	    Role x = q.remove();
	    for (Credential e: dir.forwardEdges(g, x)) {
		Role y = dir.getDest(g, e);
		if ( !visited.contains(y)) {
		    visited.add(y);
		    bfs.addVertex(y);
		    bfs.addEdge(e, e.tail(), e.head());
		    if ( dest != null && y.equals(dest)) {
			foundDest = true;
			break;
		    }
		    q.add(y);
		}
	    }
	}
	/* If foundDest is true, we know that the path from src to dest is
	 * there, so backtrack from dest to source, adding to path as we go.
	 * If we didn't find anything return the BFS as a partial proof.  Note
	 * that whatever direction the search progresses, this builds a return
	 * graph that has edges directed the same way as edges in g.
	 *
	 * If path is null, don't add the nodes to it (duh) but do decide which
	 * nodes would be kept in case dir needs that info.  E.g.
	 * findPrincipals does not need the path to the principals, just their
	 * identity.
	 */
	if ( foundDest ) {
	    Role v = dest;
	    if (path != null && !path.containsVertex(dest)) 
		path.addVertex(dest);

	    while (!v.equals(src)) {
		Collection<Credential> backEdges = dir.backwardEdges(bfs, v);

		if (backEdges.size() != 1 )
		    System.err.println("What!?");
		for (Credential e: backEdges) {
		    Role u = dir.getSource(bfs, e);

		    if ( path != null && !path.containsVertex(u)) 
			path.addVertex(u);
		    if ( path != null && !path.containsEdge(e)) 
			path.addEdge(e, e.tail(), e.head());
		    dir.keptEdge(e);
		    v = u;
		}
	    }
	} else {
	    for (Role v: bfs.getVertices() )
		if (path != null && !path.containsVertex(v)) 
		    path.addVertex(v);
	    for (Credential e: bfs.getEdges()) {
		if ( path != null && !path.containsEdge(e)) 
		    path.addEdge(e, e.tail(), e.head());
		dir.keptEdge(e);
	    }
	}
	return foundDest || dest == null;
    }
}
