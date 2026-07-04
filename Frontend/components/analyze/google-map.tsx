"use client";

import { useEffect, useRef, useState } from "react";
import { Loader } from "@googlemaps/js-api-loader";
import { MapPin } from "lucide-react";

interface GoogleMapProps {
  coordinates: { lat: number; lng: number };
  location: string;
  className?: string;
}

declare global {
  interface Window {
    gm_authFailure?: () => void;
  }
}

export function GoogleMap({ coordinates, location, className = "" }: GoogleMapProps) {
  const mapRef = useRef<HTMLDivElement>(null);
  const [mapError, setMapError] = useState(false);

  useEffect(() => {
    if (!coordinates) return;

    const apiKey = process.env.NEXT_PUBLIC_GOOGLE_MAPS_API_KEY;

    if (!apiKey) {
      console.error("Google Maps API key is not set in environment variables");
      setMapError(true);
      return;
    }

    let cancelled = false;

    // Google calls this global hook on key/billing/referrer auth failures
    // instead of throwing — without it we'd silently show its raw error dialog.
    window.gm_authFailure = () => {
      if (!cancelled) setMapError(true);
    };

    const loader = new Loader({
      apiKey,
      version: "weekly",
    });

    loader
      .load()
      .then(() => {
        if (cancelled || !mapRef.current) return;

        const map = new google.maps.Map(mapRef.current, {
          center: coordinates,
          zoom: 10,
          mapTypeId: google.maps.MapTypeId.ROADMAP,
          mapTypeControl: false,
          streetViewControl: false,
          fullscreenControl: false,
          zoomControl: true,
          // Simplified, minimalistic styling
          styles: [
            {
              featureType: "all",
              elementType: "labels.text.fill",
              stylers: [{ color: "#999999" }]
            },
            {
              featureType: "all",
              elementType: "labels.text.stroke",
              stylers: [{ visibility: "off" }]
            },
            {
              featureType: "all",
              elementType: "geometry.fill",
              stylers: [{ color: "#f5f5f5" }]
            },
            {
              featureType: "poi",
              elementType: "all",
              stylers: [{ visibility: "off" }]
            },
            {
              featureType: "road",
              elementType: "all",
              stylers: [{ saturation: -100 }, { lightness: 45 }]
            },
            {
              featureType: "transit",
              elementType: "all",
              stylers: [{ visibility: "simplified" }]
            },
            {
              featureType: "water",
              elementType: "all",
              stylers: [{ color: "#e0e0e0" }]
            }
          ]
        });

        // Simple marker without animation
        new google.maps.Marker({
          position: coordinates,
          map,
          title: location,
        });
      })
      .catch((error) => {
        console.error("Error loading Google Maps:", error);
        if (!cancelled) setMapError(true);
      });

    return () => {
      cancelled = true;
      delete window.gm_authFailure;
    };
  }, [coordinates, location]);

  if (mapError) {
    return (
      <div
        className={`w-full h-[160px] rounded border border-border bg-muted/30 flex flex-col items-center justify-center gap-1 text-center px-4 ${className}`}
      >
        <MapPin className="h-5 w-5 text-muted-foreground" />
        <p className="text-xs text-muted-foreground">Map preview unavailable</p>
        <p className="text-xs text-muted-foreground/70">{location}</p>
      </div>
    );
  }

  return <div ref={mapRef} className={`w-full h-[160px] rounded border border-border ${className}`} />;
}
