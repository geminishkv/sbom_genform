from abc import ABC, abstractmethod
from typing import Dict, Type, Optional
import logging
from utils import clean_git_url

class PackageProcessor(ABC):
    """Abstract base class for package processors."""
    
    @abstractmethod
    def process(self, purl_processed: Dict[str, str]) -> Dict[str, str]:
        """Process package-specific information."""
        pass

class DebPackageProcessor(PackageProcessor):
    def process(self, purl_processed: Dict[str, str]) -> Dict[str, str]:
        # Implementation for Debian packages
        pass

class MvnPackageProcessor(PackageProcessor):
    def process(self, purl_processed: Dict[str, str]) -> Dict[str, str]:
        # Implementation for Maven packages
        pass

class NugetPackageProcessor(PackageProcessor):
    def process(self, purl_processed: Dict[str, str]) -> Dict[str, str]:
        # Implementation for NuGet packages
        pass

class NpmPackageProcessor(PackageProcessor):
    def process(self, purl_processed: Dict[str, str]) -> Dict[str, str]:
        # Implementation for NPM packages
        pass

class PackageProcessorFactory:
    """Factory for creating package processors."""
    
    _processors: Dict[str, Type[PackageProcessor]] = {
        'deb': DebPackageProcessor,
        'maven': MvnPackageProcessor,
        'nuget': NugetPackageProcessor,
        'npm': NpmPackageProcessor,
    }
    
    @classmethod
    def get_processor(cls, package_type: str) -> Optional[PackageProcessor]:
        processor_class = cls._processors.get(package_type)
        if processor_class:
            return processor_class()
        logging.warning(f"Unsupported package type: {package_type}")
        return None

class Dependency:
    def __init__(self, name: str, version: str, dep_type: list, purl: Optional[str], path_to_sbom: str):
        self.name = name
        self.version = version
        self.dep_type = dep_type
        self.purl = purl
        self.path_to_sbom = path_to_sbom
        self.additional_info = {}
    
    def process_purl(self, purl: str) -> Dict[str, str]:
        """Process package URL with appropriate processor."""
        try:
            # Parse purl to get package type
            package_type = purl.split(':')[0] if ':' in purl else None
            
            if not package_type:
                raise ValueError(f"Invalid PURL format: {purl}")
            
            processor = PackageProcessorFactory.get_processor(package_type)
            if not processor:
                raise ValueError(f"No processor found for package type: {package_type}")
            
            # Process purl components (basic implementation)
            purl_processed = {
                'type': package_type,
                'name': self.name,
                'version': self.version
            }
            
            processed_info = processor.process(purl_processed)
            self.additional_info.update(processed_info)
            
            return processed_info
            
        except Exception as e:
            logging.error(f"Error processing PURL {purl}: {str(e)}")
            raise
    
    def clean_git_url(self, url: str) -> str:
        """Delegate to utility function."""
        return clean_git_url(url)
    
    @staticmethod
    def process_sboms(sbom_dir: str, report_dir: str) -> list:
        """Process all SBOMs in directory."""
        dependencies = []
        try:
            # Implementation for processing SBOM files
            logging.info(f"Processing SBOMs from {sbom_dir}")
            # ... SBOM processing logic ...
            return dependencies
        except Exception as e:
            logging.error(f"Error processing SBOMs: {str(e)}")
            raise
    
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Dependency):
            return NotImplemented
        return (self.name == other.name and 
                self.version == other.version)
    
    def __hash__(self) -> int:
        return hash((self.name, self.version))