from setuptools import setup, find_packages


setup(name="soc_siemapp_elk",
      version="1.0.0",
      description="Elasticsearch use case wrapper",
      author="Jean-Philippe Clipffel",
      packages=["soc_siemapp_elk" ],
      entry_points={"console_scripts": ["soc_siemapp_elk=soc_siemapp_elk.__main__:main", ]},
      install_requires=["elasticsearch", "jsonschema"],
      package_data={
            "static": ["*", ]
      }
)
