using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace ACMESharp.HTTP
{
    /// <summary>
    /// A collection of HTTP header <see cref="Link">Link</see> objects.
    /// </summary>
    /// <remarks>
    /// This collection implements multiple generic-typed enumerable interfaces
    /// but for backward compatibility, the default implemenation, i.e. the
    /// IEnumerable non-generic implementation, returns a sequence of strings
    /// which are the complete, formatted Link values.
    /// </remarks>
    public class LinkCollection : IEnumerable<string>, IEnumerable<Link>, ILookup<string, string>
    {
        private readonly List<Link> _Links = [];

        public LinkCollection() { }

        /// <param name="links">It's OK to provide a null value.</param>
        public LinkCollection(IEnumerable<Link> links)
        {
            if (links != null)
            {
                foreach (var l in links)
                {
                    Add(l);
                }
            }
        }

        /// <param name="linkValues">It's OK to provide a null value.</param>
        /// <param name="log">Logger for warnings</param>
        public LinkCollection(IEnumerable<string>? linkValues, IAcmeLogger log)
        {
            if (linkValues != null)
            {
                foreach (var lv in linkValues)
                {
                    try
                    {
                        Add(new Link(lv));
                    } 
                    catch (Exception ex)
                    {
                        log.Warning(ex, "Invalid link");
                    }
                }
            }
        }

        public IEnumerable<string> this[string key]
        {
            get
            {
                return _Links.Where(x => x.Relation == key).Select(x => x.Uri);
            }
        }

        public int Count
        {
            get
            {
                return _Links.Count;
            }
        }

        public void Add(Link link)
        {
            _Links.Add(link);
        }

        public Link? GetFirstOrDefault(string key)
        {
            return _Links.FirstOrDefault(x => x.Relation == key);
        }

        public bool Contains(string key)
        {
            return GetFirstOrDefault(key) != null;
        }

        IEnumerator<Link> IEnumerable<Link>.GetEnumerator()
        {
            return _Links.GetEnumerator();
        }

        IEnumerator<string> IEnumerable<string>.GetEnumerator()
        {
            foreach (var l in _Links)
                yield return l.Value;
        }

        IEnumerator<IGrouping<string, string>> IEnumerable<IGrouping<string, string>>.GetEnumerator()
        {
            return _Links.ToLookup(x => x.Relation, x => x.Uri).GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return ((IEnumerable<string>)this).GetEnumerator();
        }
    }
}
