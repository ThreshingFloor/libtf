# libtf
Python library for ThreshingFloor API and reducer.

# Development

```bash
# Setup virtualenv
virtualenv env
source env/bin/activate

# Install package and development dependencies
pip install -e .
pip install -r requirements-dev.txt

# Run tests
nosetests
```

# Publish new version

- Update the setup.py to include the new version
- Ensure your pypi credentials are set
- Run the following commands

```
python setup.py sdist
twine upload dist/*
```

